###############################################################################
### SNetwork Functions                                                        #
###############################################################################

Function Check-IsPortOpen ([string]$DestinationServer, [int]$Port)
{
    Try {
        $tcp  = New-Object -TypeName 'System.Net.Sockets.TcpClient'
        $con  = $tcp.BeginConnect($DestinationServer, $port, $null, $null)
        $wait = $con.AsyncWaitHandle.WaitOne(3000, $false)
        If (-not $wait) { $tcp.Close(); Return $false }
        Else {
            $failed = $false; $error.Clear()
            Try { $tcp.EndConnect($con) } Catch {}
            If (!$?) { $failed = $true }; $tcp.Close()
            If ($failed -eq $true) { Return $false } Else { Return $true }
    } } Catch { Return $false }
}


Function WhoIs
{

  #
  # Whois for the power shell
  # created by Thomas Wheeler
  # wheelert@airtop.net
  #

  $hostname = "";
  $port = 43;
  $types = '.com','.org','.net','.edu';

  #servers
   $_server = "whois.internic.net";
   $_ipserver = "whois.arin.net";

  #process arguments
  if($args.length -eq 0){
      [console]::Beep();
      Write-Host -foregroundcolor red -background black "ERROR: You must provide a domain or IP address!";
      Write-Host -foregroundcolor yellow "     USAGE: whois <DOMAIN / IP> [SERVER]";
      exit;
  }

  if($args.length -eq 1){
      $hostname = $args[0];
  }

  #check for Domain or IP
  foreach($val in $types){

      if($hostname.IndexOf($val) -eq -1){
         $_server = $_ipserver;
         break;
      }else{
          $_server = $_server;
          break;
      }

  }

  #user specified a server
  if($args.length -eq 2){
      $_server = $args[1];
  }

  #make connection
  $socket = new-object Net.Sockets.TcpClient;
  $socket.Connect($_server, $port);

  if($socket.Connected){
      Write-Host "Connected!";
      $stream = $socket.GetStream();

      $writer = new-object System.IO.StreamWriter $stream;
      $line = $hostname;
              $writer.WriteLine($line);
              $writer.Flush();
              Start-Sleep -m 5;
              #read response
              $buffer = new-object System.Byte[] 1024;
              $encoding = new-object System.Text.AsciiEncoding;
              $stream.ReadTimeout = 1000;

              do{
                  try{
                      $read = $stream.Read($buffer, 0, 1024);

                      if($read -gt 0){
                          $foundmore = $true;
                          $outputBuffer += ($encoding.GetString($buffer, 0, $read));
                      }
                  }catch{
                      $foundMore = $false;
                      $read = 0;
                  }
              }while($read -gt 0);
              #display results
              $outputBuffer;
      #close Socket
      $socket.Close();

  }else{
      Write-Host "Unable to Connect!";
  }

}
