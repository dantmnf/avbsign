package xyz.cirno.avb.verify;

import xyz.cirno.avb.ParsedVerifiedBootMetaImage;
import xyz.cirno.avb.VerifiedBootFooter;

public record PartitionRecord(String name, ParsedVerifiedBootMetaImage vbmetaImage,
                              VerifiedBootFooter footer) {
}
