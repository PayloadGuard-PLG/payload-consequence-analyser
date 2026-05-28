// verification/dafny/structural_drift.dfy
//
// Machine-checked verification of PayloadGuard L4 structural drift assessment.
// Verifies the dual-gate property: DESTRUCTIVE requires BOTH deletion_ratio >
// threshold AND deleted_count >= min_deletion_count. Neither condition alone
// is sufficient, preventing false positives on files with very few symbols.
//
// Tool:    Dafny 4.x — Boogie + Z3 backend
// Verify:  dafny verify verification/dafny/structural_drift.dfy

method AssessStructuralDrift(
    original_count:           nat,
    deleted_count:            nat,
    deletion_ratio_threshold: real,
    min_deletion_count:       nat
) returns (status: string, deletion_ratio: real)

    requires deleted_count <= original_count
    requires 0.0 < deletion_ratio_threshold < 1.0
    requires min_deletion_count >= 1

    // S1: status is one of two valid values
    ensures status == "SAFE" || status == "DESTRUCTIVE"

    // S2: deletion ratio is in [0, 1]
    ensures 0.0 <= deletion_ratio <= 1.0

    // S3–S4: DESTRUCTIVE implies both gate conditions hold
    ensures status == "DESTRUCTIVE" ==> deletion_ratio > deletion_ratio_threshold
    ensures status == "DESTRUCTIVE" ==> deleted_count >= min_deletion_count

    // S5: no deletions implies SAFE
    ensures deleted_count == 0 ==> status == "SAFE"

    // S6: empty original implies SAFE (ratio = 0, below any positive threshold)
    ensures original_count == 0 ==> status == "SAFE"

    // S7: biconditional — dual-gate is both necessary and sufficient
    ensures (status == "DESTRUCTIVE") <==>
            (deletion_ratio > deletion_ratio_threshold &&
             deleted_count >= min_deletion_count)
{
    if original_count == 0 {
        deletion_ratio := 0.0;
    } else {
        deletion_ratio := (deleted_count as real) / (original_count as real);
    }

    if deletion_ratio > deletion_ratio_threshold &&
       deleted_count >= min_deletion_count {
        status := "DESTRUCTIVE";
    } else {
        status := "SAFE";
    }
}
