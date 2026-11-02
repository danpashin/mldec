#ifndef BridgingHeader_h
#define BridgingHeader_h

#import <Foundation/Foundation.h>

int mremap_encrypted(void* addr, size_t len, uint32_t cryptid, uint32_t cputype, uint32_t cpusubtype);

@interface MLCloudSession: NSObject
- (instancetype)initWithTeamIdentifier:(NSString *)teamID;
- (NSData *)fetchKeyResponseFromServerForKeyID:(NSString *)keyID signedKeyRequest:(NSData *)request error:(NSError *__autoreleasing *)error;
@end

@interface MLFairPlayKeyLoadingSession: NSObject
- (NSData *)generateKeyRequestForKeyIdentifier:(NSString *)keyID teamIdentifier:(NSString *)teamID error:(NSError *__autoreleasing *)error;
- (NSData *)generatePersistentKeyBlobFromKeyResponse:(NSData *)response error:(NSError *__autoreleasing *)error;
@end

@interface MLFairPlayDecryptSessionManager: NSObject
- (BOOL)startDecryptionOfModelAtPath:(NSString *)path usingKeyBlob:(NSData *)keyBlob teamIdentifier:(NSString *)teamID error:(NSError *__autoreleasing *)error;
- (void)stopDecryptionOfModelAtPath:(NSString *)path;
@end

@interface MLPersistentKeyStorage: NSObject
+ (BOOL)storeKeyBlob:(nonnull NSData *)keyBlob forKeyIdentifier:(nonnull NSString *)keyID error:(NSError *__autoreleasing *)error;
+ (nullable NSData *)retrieveKeyBlobForKeyIdentifier:(NSString *)keyID;
@end

#endif /* BridgingHeader_h */
