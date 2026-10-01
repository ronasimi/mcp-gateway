rule Suspicious_Encoded_Powershell_Command
{
  meta:
    description = "Flags common encoded PowerShell command indicators for defensive triage"
  strings:
    $a = "powershell" nocase ascii wide
    $b1 = " -enc " nocase ascii wide
    $b2 = " -encodedcommand " nocase ascii wide
  condition:
    $a and any of ($b*)
}

rule Suspicious_Command_Download_Execute
{
  meta:
    description = "Flags common download-and-execute command combinations for defensive triage"
  strings:
    $curl = "curl " nocase ascii wide
    $wget = "wget " nocase ascii wide
    $pipe_sh = "| sh" nocase ascii wide
    $pipe_bash = "| bash" nocase ascii wide
  condition:
    ($curl or $wget) and ($pipe_sh or $pipe_bash)
}

rule Suspicious_Private_Key_Material
{
  meta:
    description = "Flags embedded private-key material"
  strings:
    $rsa = "-----BEGIN RSA PRIVATE KEY-----" ascii
    $ec = "-----BEGIN EC PRIVATE KEY-----" ascii
    $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
    $pkcs8 = "-----BEGIN PRIVATE KEY-----" ascii
  condition:
    any of them
}
