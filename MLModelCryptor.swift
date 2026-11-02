import Foundation

extension URL {
    func relativePath(to base: URL) -> String {
        path.replacingOccurrences(of: base.path, with: "").trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }
}

@objcMembers class MLEncryptedModel: NSObject {
    let modelUrl: URL

    let cryptKeyID: String

    private let manager = MLFairPlayDecryptSessionManager()

    init(modelUrl: URL) throws {
        self.modelUrl = (modelUrl as NSURL).resolvingSymlinksInPath!

        let cryptInfoURL = modelUrl.appendingPathComponent("encryptionInfo").appendingPathComponent("coremldata.bin")

        let cryptInfo = try MLEncryptionInfo(path: cryptInfoURL.path)
        self.cryptKeyID = cryptInfo.keyID
    }

    func decrypt(teamID: String, to outURL: URL) throws {
        let keyBlob = try getKeyBlob(teamID: teamID)
        try manager.startDecryptionOfModel(atPath: modelUrl.path, usingKeyBlob: keyBlob, teamIdentifier: teamID)
        defer { manager.stopDecryptionOfModel(atPath: modelUrl.path) }

        print("Using \(teamID) and \(cryptKeyID)...")

        let outDir = (outURL as NSURL).resolvingSymlinksInPath!.appendingPathComponent(modelUrl.lastPathComponent)
        if outDir == modelUrl {
            fatalError("Target dir can't be the same as source")
        }
        let targetModelURL = outDir.appendingPathComponent(modelUrl.lastPathComponent, isDirectory: true)

        let fm = FileManager.default

        for case let relFilePath as String in fm.enumerator(atPath: modelUrl.path)! {
            let sourceURL = modelUrl.appendingPathComponent(relFilePath)

            let fileAttributes = try sourceURL.resourceValues(forKeys:[.isRegularFileKey])
            if !fileAttributes.isRegularFile! {
                continue
            }

            if sourceURL.path.contains("encryptionInfo") {
                continue
            }

            do {
                try autoreleasepool {
                    let file = try MLEncryptedFile(path: sourceURL.path)
                    let decryped = try file.decrypt()

                    let targetFileURL = outDir.appendingPathComponent(relFilePath)
                    try fm.createDirectory(at: targetFileURL.deletingLastPathComponent(), withIntermediateDirectories: true)

                    try decryped.write(to: targetFileURL)
                }

                print("Decrypted \(sourceURL.path)")
            } catch {
                print("\(sourceURL.path) failed with error: \(error)")

                try? fm.removeItem(at: targetModelURL)
                break
            }
        }
    }

    private func getKeyBlob(teamID: String) throws -> Data  {
        if let keyBlob = MLPersistentKeyStorage.retrieveKeyBlob(forKeyIdentifier: cryptKeyID) {
            print("Got keyblob from storage")
            return keyBlob
        }

        let fpsession = MLFairPlayKeyLoadingSession()
        let request = try fpsession.generateKeyRequest(forKeyIdentifier: cryptKeyID, teamIdentifier: teamID)

        let cloudSession = MLCloudSession(teamIdentifier: teamID)!
        let response = try cloudSession.fetchKeyResponseFromServer(forKeyID: cryptKeyID, signedKeyRequest: request)

        let keyBlob = try fpsession.generatePersistentKeyBlob(fromKeyResponse: response)
        try MLPersistentKeyStorage.storeKeyBlob(keyBlob, forKeyIdentifier: cryptKeyID)

        return keyBlob
    }
}

class MLEncryptedFile: CustomStringConvertible {
    static let MIN_SIZE: Int8 = 64

    private let fd: Int32

    let origContents: UnsafeMutableRawBufferPointer

    let version: Int16
    let headerSize: Int8
    let dataLength: Int64
    let encryptedPages: Int64

    var rawDataBuf: UnsafeMutableRawBufferPointer {
        let dataStart = origContents.baseAddress!.advanced(by: Int(headerSize))
        return UnsafeMutableRawBufferPointer(start: dataStart, count: Int(dataLength))
    }

    var description: String {
        return "<\(type(of: self)): version = \(version); headerSize = \(headerSize); dataLen = \(dataLength); encryptedPages = \(encryptedPages)>"
    }

    init(path: String) throws {
        var statBuf = stat()
        path.withCString { cPath in
            _ = stat(cPath, &statBuf)
        }
        let size = Int(statBuf.st_size)

        if size < Self.MIN_SIZE {
            throw NSError(domain: NSPOSIXErrorDomain, code:Int(EINVAL))
        }

        fd = path.withCString { open($0, 0) }
        if fd == -1 {
            throw NSError(domain: NSPOSIXErrorDomain, code:Int(errno))
        }

        let contentsPtr = mmap(nil, size, PROT_READ, MAP_PRIVATE, fd, 0)
        if contentsPtr == UnsafeMutableRawPointer(bitPattern: -1) {
            close(fd)

            throw NSError(domain: NSPOSIXErrorDomain, code:Int(errno))
        }

        origContents = UnsafeMutableRawBufferPointer(start: contentsPtr, count: size)

        let magic = origContents.load(as: Int32.self)
        if magic != _OSSwapInt32(0x4C4D4E45) {
            munmap(contentsPtr, size)
            close(fd)

            throw NSError(domain: NSPOSIXErrorDomain, code: Int(EINVAL))
        }

        version = origContents.load(fromByteOffset: 0x4, as: Int16.self)

        if version == 0x1 {
            headerSize = Self.MIN_SIZE
        } else {
            headerSize = origContents.load(fromByteOffset: 0x7, as: Int8.self)
        }

        dataLength = origContents.load(fromByteOffset: 0x8, as: Int64.self)
        encryptedPages = origContents.load(fromByteOffset: 0x10, as: Int64.self)
    }

    deinit {
        munmap(origContents.baseAddress!, origContents.count)
        close(fd)
    }

    func decrypt() throws -> Data {
        let rawData = rawDataBuf

        if encryptedPages != 0 {
            if mremap_encrypted(origContents.baseAddress!, Int(encryptedPages) << 0xC, 0x2, 0xABCD, 0) != 0 {
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(EIO))
            }
        }

        return NSData(bytesNoCopy: rawData.baseAddress!, length: rawData.count, freeWhenDone: false) as Data
    }
}

class MLEncryptionInfo: MLEncryptedFile {
    var keyID: String {
        let rawData = rawDataBuf
        let keyIdLen = rawData.load(fromByteOffset: 0x0, as: Int64.self)
        let keyIDStart = rawData.baseAddress!.advanced(by: MemoryLayout<Int64>.size)

        return NSString(bytes: keyIDStart, length: Int(keyIdLen), encoding: NSUTF8StringEncoding)! as String
    }
}
