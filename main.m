#import <Foundation/Foundation.h>
#import "mldec-Swift.h"

int main(int argc, char *argv[], char *envp[]) {
    if (argc != 4) {
        printf("Usage: %s <TEAM_ID> <ENCRYPTED_MODEL_PATH> <DECRYPTED_MODEL_PATH>\n", argv[0]);
        printf("    TEAM_ID is the Team identifier which app was signed with\n");
        printf("    ENCRYPTED_MODEL_PATH - path to the encrypted MLModel\n");
        printf("    DECRYPTED_MODEL_PATH - path to the directory in which decrypted MLModel will be written\n");

        return -1;
    }

    if (*argv[1] == '\0' || *argv[2] == '\0' || *argv[3] == '\0') {
        printf("Empty arguments\n");
        return -1;
    }

    NSString *teamID = @(argv[1]);
    NSURL *modelURL = [NSURL fileURLWithPath:@(argv[2])];
    NSURL *targetDirURL = [NSURL fileURLWithPath:@(argv[3])];

    NSError *error = nil;
    MLEncryptedModel *model = [[MLEncryptedModel alloc] initWithModelUrl:modelURL error:&error];
    if (error) {
        printf("Got an error: %s\n", error.description.UTF8String);
        return -1;
    }

    [model decryptWithTeamID:teamID to:targetDirURL error:&error];
    if (error) {
        printf("Got an error: %s\n", error.description.UTF8String);
        return -1;
    }

    return 0;
}
