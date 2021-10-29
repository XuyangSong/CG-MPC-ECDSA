use thiserror::Error;

/// Represents errors.
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum MulEcdsaError {
    #[error("Open dlcommitment failed")]
    OpenDLCommFailed,
    #[error("Open zk-pok commitment failed")]
    OpenCommZKFailed,
    #[error("Verify DLog failed")]
    VrfyDlogFailed,
    #[error("The size of zr excceeds sample size")]
    ZrExcceedSize,
    #[error("Verify promise sigma protocol failed")]
    VrfyPromiseFailed,
    #[error("The return of x_coor() in None")]
    XcoorNone,
    #[error("Verify two-party ECDSA signature failed")]
    VrfyTwoECDSAFailed,
    #[error("Verify class group pk failed")]
    VrfyClassGroupFailed,
    #[error("Verify received DL commitment zk failed")]
    VrfyRecvDLComZKFailed,
    #[error("Get index failed")]
    GetIndexFailed,
    #[error("Serialize failed ")]
    SerializeFailed,
    #[error("Verify VSS failed")]
    VrfyVSSFailed,
    #[error("Generate Vss in phase four failed")]
    GenVSSFailed,
    #[error("Get multiparty ecdsa keygen phase one and phase two message failed")]
    GetPhaseOneTwoMsgFailed,
    #[error("Verify multiparty ecdsa keygen phase one message failed")]
    VrfyPhaseOneMsgFailed,
    #[error("Handle multiparty ecdsa keygen phase three message failed")]
    HandlePhaseThreeMsgFailed,
    #[error("Handle multiparty ecdsa keygen phase four message failed")]
    HandlePhaseFourMsgFailed,
    #[error("Handle multiparty ecdsa keygen phase five message failed")]
    HandlePhaseFiveMsgFailed,
    #[error("To string failed")]
    ToStringFailed,
    #[error("From string failed")]
    FromStringFailed,
    #[error("Party numbers less than the value of threshold in multiparty ecdsa keygen")]
    PartyLessThanThreshold,
    #[error("Left not equal to Right")]
    LeftNotEqualRight,
    #[error("Verify multiparty ecdsa sign phase one message failed")]
    VrfySignPhaseOneMsgFailed,
    #[error("Handle multiparty ecdsa sign phase two message failed")]
    HandleSignPhaseTwoMsgFailed,
    #[error("Open general commitment failed")]
    OpenGeCommFailed,
    #[error("Verify HomoElGamal failed")]
    VrfyHomoElGamalFailed,
    #[error("Verify sum_a_t failed")]
    VrfySumatFailed,
    #[error("Get multiparty ecdsa sign phase one message failed")]
    GetSignPhaseOneMsgFailed,
    #[error("Handle multiparty ecdsa sign phase one message failed")]
    HandleSignPhaseOneMsgFailed,
    #[error("Compute delta sum msg in multiparty ecdsa sign phase two failed")]
    ComputeDeltaSumFailed,
    #[error("Compute r_x in multiparty ecdsa sign failed")]
    ComputeRxFailed,
    #[error("Handle multiparty ecdsa sign phase four message failed")]
    HandleSignPhaseFourMsgFailed,
    #[error("Handle multiparty ecdsa sign phase five step two  message failed")]
    HandleSignPhaseFiveStepTwoMsgFailed,
    #[error("Handle multiparty ecdsa sign phase five step five message failed")]
    HandleSignPhaseFiveStepFiveMsgFailed,
    #[error("Generate multiparty ecdsa sign phase five step four message failed")]
    GenerateSignPhaseFiveStepFourMsgFailed,
    #[error("Handle multiparty ecdsa sign phase five step eight message failed")]
    HandleSignPhaseFiveStepEightMsgFailed,
    #[error("Verify ElgamalProof failed")]
    VrfyElgamalProofFailed,
    #[error("Verify CLEncProof failed")]
    VrfyClEncProofFailed,
    #[error("File read to string failed")]
    FileReadFailed,
    #[error("File write failed")]
    FileWriteFailed,
    #[error("Not load keygen result")]
    NotLoadKeyGenResult,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("General error")]
    GeneralError,
}
