# this is a Pester test file

#region Further Reading
# http://www.powershellmagazine.com/2014/03/27/testing-your-powershell-scripts-with-pester-assertions-and-more/
#endregion


Import-Module .\genKeyHelper.psd1 -Force -Verbose
# describes the function New-SecureRandom
Describe 'New-SecureRandom' {
  Context 'Running without arguments'   {
    It 'runs without errors' {
      { New-SecureRandom } | Should Not Throw
    }
    It 'does something' {
      $ret = New-SecureRandom 
      $ret | Should BeOfType Org.BouncyCastle.Security.SecureRandom
    }
  }
}
# describes the function New-RSAKeyPair
Describe 'New-RSAKeyPair' {
  Context 'Running without arguments'   {
    It 'runs without errors' {
      { New-RSAKeyPair } | Should Not Throw
    }
    It 'does something' {
      New-RSAKeyPair | Should Not BeNullOrEmpty
    }
  }
}
