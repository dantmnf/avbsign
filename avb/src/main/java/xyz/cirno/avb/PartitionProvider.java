package xyz.cirno.avb;

import java.nio.channels.SeekableByteChannel;

public interface PartitionProvider {
    SeekableByteChannel openPartition(String name);
}
