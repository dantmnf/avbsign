package xyz.cirno.avb.verify;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class AvbVerifyResult {
    public final String rootImageName;
    public final Map<String, PartitionRecord> partitionRecords;
    public final List<VerificationIssue> issues;
    public final Set<AvbVerifier.PartitionReference> partitionReferences;

    /* internal */ AvbVerifyResult(String rootImageName, Map<String, PartitionRecord> partitionRecords, List<VerificationIssue> issues, Set<AvbVerifier.PartitionReference> references) {
        this.rootImageName = rootImageName;
        this.partitionRecords = Collections.unmodifiableMap(partitionRecords);
        this.issues = Collections.unmodifiableList(issues);
        this.partitionReferences = Collections.unmodifiableSet(references);
    }

    public boolean hasIssues() {
        return !issues.isEmpty();
    }
}
