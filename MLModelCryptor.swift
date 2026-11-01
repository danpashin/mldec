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
        let cryptInfo = try FileHandle(forReadingFrom: cryptInfoURL)

        try cryptInfo.seek(toOffset: 0x60)
        let keyIDLenData = try cryptInfo.read(upToCount: 8)!

        var keyIDLen: Int = 0
        _ = withUnsafeMutableBytes(of: &keyIDLen) { buf in
            keyIDLenData.copyBytes(to: buf, count: 8)
        }

        let keyID = try cryptInfo.read(upToCount: keyIDLen)!
        self.cryptKeyID = String(data: keyID, encoding: .utf8)!
    }

    func decrypt(teamID: String, to outURL: URL) throws {
        let keyBlob = try getKeyBlob(teamID: teamID)
        try manager.startDecryptionOfModel(atPath: modelUrl.path, usingKeyBlob: keyBlob, teamIdentifier: teamID)
        defer { manager.stopDecryptionOfModel(atPath: modelUrl.path) }

        let outDir = (outURL as NSURL).resolvingSymlinksInPath!.appendingPathComponent(modelUrl.lastPathComponent)
        if outDir == modelUrl {
            fatalError("Target dir can't be the same as source")
        }

        let fm = FileManager.default

        let enumerator = fm.enumerator(at: modelUrl, includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey])!
        for case let fileURL as URL in enumerator {
            let sourceURL = (fileURL as NSURL).resolvingSymlinksInPath!

            let fileAttributes = try sourceURL.resourceValues(forKeys:[.isRegularFileKey, .fileSizeKey])
            if !fileAttributes.isRegularFile! {
                continue
            }

            if sourceURL.path.contains("encryptionInfo") {
                continue
            }

            let size = fileAttributes.fileSize!
            if size <= 0x50 {
                print("Can't process \(sourceURL.path) as it is not a valid DB")
                continue
            }

            guard let sourceHandle = try? FileHandle(forReadingFrom: sourceURL),
                  let fileData = mmap(nil, size, 1, 2, sourceHandle.fileDescriptor, 0),
                  fileData != UnsafeMutableRawPointer(bitPattern: -1)
            else {
                print("Can't mmap \(sourceURL.path)")
                continue
            }

            defer { munmap(fileData, size) }

            let targetURL = outDir.appendingPathComponent(sourceURL.relativePath(to: modelUrl))
            try fm.createDirectory(at: targetURL.deletingLastPathComponent(), withIntermediateDirectories: true)

            let encryptedPages = fileData.load(fromByteOffset: 0x10, as: Int8.self)
            if encryptedPages == 0 {
                print("\(sourceURL.path) is not encrypted")
                try fm.copyItem(at: sourceURL, to: targetURL)
                continue
            }

            if mremap_encrypted(fileData, size, 0x2, 0xABCD, 0) != 0 {
                print("Remap for \(sourceURL.path) failed")
                continue
            }

            let decryptedData = NSData(bytesNoCopy: fileData, length: size, freeWhenDone: false)
            try decryptedData.write(to: targetURL)

            print("Decrypted \(sourceURL.path)")
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
