package xyz.cirno.avb.verify;

import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.Objects;

import xyz.cirno.avb.AvbPublicKey;

public interface VerificationIssue {
    record InvalidPartitionData(String partitionName) implements VerificationIssue {
        public @NotNull String toString() {
            return "InvalidPartitionData(partitionName=" + partitionName + ")";
        }
    }

    record HashMismatch(
            String vbmetaPartition,
            int descriptorIndex,
            long actualSize,
            byte[] actualHash
    ) implements VerificationIssue {
        @Override
        public @NotNull String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("HashMismatch(vbmetaPartition=").append(vbmetaPartition)
                    .append(", descriptorIndex=").append(descriptorIndex)
                    .append(", actualSize=").append(actualSize)
                    .append(", actualHash=");
            for (byte b : actualHash) {
                sb.append(String.format("%02x", b));
            }
            sb.append(")");
            return sb.toString();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            HashMismatch that = (HashMismatch) o;
            return descriptorIndex == that.descriptorIndex &&
                    actualSize == that.actualSize &&
                    Objects.equals(vbmetaPartition, that.vbmetaPartition) &&
                    Arrays.equals(actualHash, that.actualHash);
        }

        @Override
        public int hashCode() {
            return Objects.hash(getClass(), vbmetaPartition, descriptorIndex, actualSize, Arrays.hashCode(actualHash));
        }
    }

    record PublicKeyMismatch(
            String vbmetaPartition,
            int descriptorIndex,
            AvbPublicKey actualPublicKey
    ) implements VerificationIssue {
        @Override
        public @NotNull String toString() {
            return "PublicKeyMismatch(vbmetaPartition=" + vbmetaPartition +
                    ", descriptorIndex=" + descriptorIndex +
                    ", actualPublicKey=" + actualPublicKey + ")";
        }
    }

    record InvalidSignature(String vbmetaPartition) implements VerificationIssue {
        public @NotNull String toString() {
            return "InvalidSignature(partitionName=" + vbmetaPartition + ")";
        }
    }
}
