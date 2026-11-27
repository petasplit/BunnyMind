package bunnyfix

import (
 "crypto/ed25519"
 "errors"
 "fmt"

 "github.com/enowdev/antares/internal/bunnybuild"
)

type BuildBoundPair struct{
 Pair Pair `json:"pair"`
 BeforeBuild bunnybuild.Signed `json:"before_build"`
 AfterBuild bunnybuild.Signed `json:"after_build"`
}
type BuildBoundResult struct{
 Comparison Result `json:"comparison"`
 BeforeArtifactSHA256 string `json:"before_artifact_sha256"`
 AfterArtifactSHA256 string `json:"after_artifact_sha256"`
 ArtifactMeasurementsAuthenticated bool `json:"artifact_measurements_authenticated"`
 DeploymentIdentityVerified bool `json:"deployment_identity_verified"`
 Disclaimer string `json:"disclaimer"`
}
// CompareBuildBound verifies locally measured file digests and binds them to
// signed observations for both lab runs. It does not verify whether the
// responding server executed the measured file. DeploymentIdentityVerified
// therefore always remains false in this version.
func CompareBuildBound(pub ed25519.PublicKey,b BuildBoundPair)(BuildBoundResult,error){
 before,err:=bunnybuild.Verify(pub,b.BeforeBuild)
 if err!=nil{return BuildBoundResult{},fmt.Errorf("before artifact measurement: %w",err)}
 after,err:=bunnybuild.Verify(pub,b.AfterBuild)
 if err!=nil{return BuildBoundResult{},fmt.Errorf("after artifact measurement: %w",err)}
 first,second:=b.Pair.BeforePlan,b.Pair.AfterPlan
 if before.EngagementID!=first.EngagementID||before.RunID!=first.RunID||
 after.EngagementID!=second.EngagementID||after.RunID!=second.RunID{
  return BuildBoundResult{},errors.New("signed artifact measurements are not bound to the declared engagement/run IDs")
 }
 if first.BuildSHA256==""||second.BuildSHA256==""||
 first.BuildSHA256!=before.ArtifactSHA256||second.BuildSHA256!=after.ArtifactSHA256{
  return BuildBoundResult{},errors.New("signed observations do not identify their separately measured artifact digest")
 }
 if before.ArtifactSHA256==after.ArtifactSHA256{
  return BuildBoundResult{},errors.New("before and after measured artifacts have identical SHA-256")
 }
 // Compare invokes the authenticated owner/foreign/anonymous checks, now
 // including exact build fingerprint equality for every signed receipt.
 comparison,err:=Compare(pub,b.Pair)
 if err!=nil{return BuildBoundResult{},err}
 return BuildBoundResult{
  Comparison:comparison,
  BeforeArtifactSHA256:before.ArtifactSHA256,
  AfterArtifactSHA256:after.ArtifactSHA256,
  ArtifactMeasurementsAuthenticated:true,
  DeploymentIdentityVerified:false,
  Disclaimer:"The same pinned recorder key signed file-byte measurements and synthetic HTTP observations. This authenticates those claims, but does not prove that either live server executed the measured artifact, nor that a production fix was deployed.",
 },nil
}
