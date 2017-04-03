using assembly BouncyCastle.Crypto.dll

using namespace Org.BouncyCastle.Crypto
using namespace Org.BouncyCastle.Crypto.Parameters
using namespace Org.BouncyCastle.Crypto.Prng
using namespace Org.BouncyCastle.Security
using namespace Org.BouncyCastle.OpenSsl

function New-SecureRandom{  
  $randomGenerator = [CryptoApiRandomGenerator]::new()
  $random = [SecureRandom]::new($randomGenerator)

  $random
}

function Convertto-bytes([Parameter(Mandatory=$true)][int] $num) {
    [byte[]] $bts = [BitConverter]::GetBytes($num)
    if ([BitConverter]::IsLittleEndian){
        [Array]::Reverse($bts)
    }

    $bts
}

function New-RSAKeyPair {
    $r = New-SecureRandom
    $keyGenParameters = [KeyGenerationParameters]::new($r,2048)
    $keyPairGenerator = [Generators.RsaKeyPairGenerator]::new()
    $keyPairGenerator.Init($keyGenParameters)
    $keyPairGenerator.GenerateKeyPair()
}

function Get-PEM ($keypair, $keytype) {
    $str = [io.stringwriter]::new()
    $pemWriter = [PemWriter]::new($str)
    switch ($keytype) {
        "private" {$pemWriter.WriteObject($keypair.Private)}
        "public" {$pemWriter.WriteObject($keypair.Public)}
    }
    
    $pemWriter.Writer.Flush()
    $pemWriter.Writer.ToString()
}

function Get-RSASSHFormattedKey($PEMKey) {
    $srReader = [IO.StringReader]::new($PEMKey)
    $pemReader = [PemReader]::new($srReader)
    $sshrsa_bytes  =   [Text.Encoding]::Default.GetBytes("ssh-rsa")
    $r = $pemReader.ReadObject()
    if ($r -is [RsaKeyParameters]){
        $n = $r.Modulus.ToByteArray()
        $e = $r.Exponent.ToByteArray()
    }
    else {
        $n = $r.Private.Modulus.ToByteArray()
        $e = $r.Private.Exponent.ToByteArray()
    }

    <#
      For an ssh-rsa key, the PEM-encoded data is a series of (length, data) pairs. The length is encoded as four octets (in big-endian order). 
      The values encoded are:

      algorithm name (one of (ssh-rsa, ssh-dsa)). This duplicates the key type in the first field of the public key.
      RSA exponent
      RSA modulus
    #>

    $ms =  [IO.MemoryStream]::new()
    $ms.Write((Convertto-bytes $sshrsa_bytes.Length),0,4)
    $ms.Write($sshrsa_bytes,0,$sshrsa_bytes.Length)
    $ms.Write((Convertto-bytes $e.Length),0,4)
    $ms.Write($e, 0, $e.Length)
    $ms.Write((Convertto-bytes $n.Length), 0, 4)
    $ms.Write($n, 0, $n.Length)
    $ms.Flush()

    $buffer64 = [Convert]::ToBase64String($ms.ToArray())
    "ssh-rsa `r`n{0}" -f $buffer64
}

<#
$keypair = New-RSAkeyPair
"public key pEM"
$pubPEM = Get-PEM -keypair $keypair -keytype public
$pubPEM

"private key PEM"
$privPEM = Get-PEM -keypair $keypair -keytype private
$privPEM

"private key rsa-ssh formatted"
Get-RSASSHFormattedKey -PEMKey $privPEM

"public key rsa-ssh formatted"
Get-RSASSHFormattedKey -PEMKey $pubPEM
#>