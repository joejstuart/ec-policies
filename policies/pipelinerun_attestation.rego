package hacbs.contract.pipelinerun_attestation


deny[msg] {
    t := input.bad == 1
    not t
    msg := "bad"
}
