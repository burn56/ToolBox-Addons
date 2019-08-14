[CmdletBinding()]param (    [string]$Company    )
#region functions

# Add WPF and Windows Forms assemblies
try {
    Add-Type -AssemblyName PresentationCore, PresentationFramework, WindowsBase, system.windows.forms
}
catch {
    Throw 'Failed to load Windows Presentation Framework assemblies.'
}

Function New-WPFDialog() {
    <#
    .SYNOPSIS
    This neat little function is based on the one from Brian Posey's Article on Powershell GUIs

    .DESCRIPTION
      I re-factored a bit to return the resulting XaML Reader and controls as a single, named collection.

    .PARAMETER XamlData
     XamlData - A string containing valid XaML data

    .EXAMPLE

      $MyForm = New-WPFDialog -XamlData $XaMLData
      $MyForm.Exit.Add_Click({...})
      $null = $MyForm.UI.Dispatcher.InvokeAsync{$MyForm.UI.ShowDialog()}.Wait()

    .NOTES
    Place additional notes here.

    .LINK
      http://www.windowsnetworking.com/articles-tutorials/netgeneral/building-powershell-gui-part2.html

    .INPUTS
     XamlData - A string containing valid XaML data

    .OUTPUTS
     a collection of WPF GUI objects.
    #>

    Param([Parameter(Mandatory = $True, HelpMessage = 'XaML Data defining a GUI', Position = 1)]
        [string]$XamlData)

    # Create an XML Object with the XaML data in it
    [xml]$xmlWPF = $XamlData

    # Create the XAML reader using a new XML node reader, UI is the only hard-coded object name here
    Set-Variable -Name XaMLReader -Value @{ 'UI' = ([Windows.Markup.XamlReader]::Load((new-object -TypeName System.Xml.XmlNodeReader -ArgumentList $xmlWPF))) }

    # Create hooks to each named object in the XAML reader
    $Elements = $xmlWPF.SelectNodes('//*[@Name]')
    ForEach ( $Element in $Elements ) {
        $VarName = $Element.Name
        $VarValue = $XaMLReader.UI.FindName($Element.Name)
        $XaMLReader.Add($VarName, $VarValue)
    }

    return $XaMLReader
}

Function ConvertTo-BinaryIP {
    param([string] $IPV4Address)
    $ByteStrings = foreach ($IPByte in ([System.Net.IPAddress]$IPV4Address).GetAddressBytes()) {
        ([System.Convert]::ToString($IPByte, 2)).PadLeft(8, '0')
    }
    return ($ByteStrings -join '')
}

Function ConvertTo-BinaryMask {
    param([int] $MaskBits)
    return $($(for ( $i = 1; $i -le $MaskBits; $i += 1) { '1' }) -join '').PadRight(32, '0')
}

Function ConvertTo-IPString {
    param ([string] $BinaryIPStr)
    return ([System.Net.IPAddress]"$([System.Convert]::ToInt64($BinaryIPStr,2))").IPAddressToString
}

Function Get-NotIPString {
    param([string]$BinString)
    $StrArray = $BinString.ToCharArray()
    return $($(for ( $i = 0; $i -le 31; $i += 1) { 1 - [int16][string]$StrArray[$i] }) -join '')
}

Function Band-IPStrings {
    param([string] $Left,
        [string] $Right)
    return $(for ( $i = 0; $i -le 31; $i += 1) { [int16][string]$Left.ToCharArray()[$i] -band [int16][string]$Right.ToCharArray()[$i] }) -join ''
}
Function Bor-IPStrings {
    param([string] $Left,
        [string] $Right)
    return $(for ( $i = 0; $i -le 31; $i += 1) { [int16][string]$Left.ToCharArray()[$i] -bor [int16][string]$Right.ToCharArray()[$i] }) -join ''
}

Function Validate-IP {
    param([string]$IP)
    $return = $false
    try {
        [IPAddress]$IP
        $return = $true
    }
    catch {
        $return = $false
    }
    return $return
}
#endregion

#region Form
$FormBackColor = 'F2F2F2'
$FormForeColor = '000000'
$PanelBackColor = 'FFFFFF'
$TextBoxBackColor = 'FFFFFF'
$TextBoxForeColor = '000000'
$TextBlockBackColor = 'F2F2F2'
$TextBlockForeColor = '57B1FD'
$ButtonBackColor = 'C2C2C2'
# This is the XaML that defines the GUI.
$WPFXamL = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="CONTOSO Subnet Calculator" Height="600" Width="480" Background="#FF$FormBackColor" Foreground="#FF$FormForeColor" ResizeMode="NoResize" Name="RootWindow">
    <Grid Background="#FF$FormBackColor">
        <Rectangle Fill="#FF$PanelBackColor" Height="86" Margin="4,5,4,0" VerticalAlignment="Top"/>
        <Rectangle Fill="#FF$PanelBackColor" Height="125" Margin="4,155,4,0" VerticalAlignment="Top"/>
        <Rectangle Fill="#FF$PanelBackColor" Height="215" Margin="4,285,4,-18" VerticalAlignment="Top"/>
        <Rectangle Fill="#FF$PanelBackColor" Height="52" Margin="4,505,4,0" VerticalAlignment="Top"/>
        <TextBlock Name="BigContoso" Margin="0" TextWrapping="Wrap" Text="CONTOSO" VerticalAlignment="Top" Foreground="#FF737373" FontFamily="Segoe UI Semibold" FontSize="48" TextAlignment="Center" HorizontalAlignment="Center" />
        <TextBlock Name="Subtitle" Margin="0,53,0,0" TextWrapping="Wrap" Text="Subnet Calculator" VerticalAlignment="Top" Foreground="#FF57B1FD" FontSize="24" HorizontalAlignment="Center"/>
        <TextBlock Name="IPv4Label" HorizontalAlignment="Left" Margin="50,96,0,0" TextWrapping="Wrap" Text="IPv4 Address" VerticalAlignment="Top"/>
        <TextBlock Name="MaskLabel" HorizontalAlignment="Left" Margin="200,96,0,0" TextWrapping="Wrap" Text="Subnet Mask" VerticalAlignment="Top"/>
        <TextBlock Name="MaskBitsLabel" HorizontalAlignment="Left" Margin="350,96,0,0" TextWrapping="Wrap" Text="Mask Bits" VerticalAlignment="Top"/>
        <TextBox Name="IPAddress" HorizontalAlignment="Left" Height="20" Margin="50,112,0,0" TextWrapping="Wrap" Text="172.16.0.1" VerticalAlignment="Top" Width="125" Background="#FF$TextBoxBackColor" Foreground="#FF$TextBoxForeColor"/>
        <TextBox Name="Subnet" HorizontalAlignment="Left" Height="20" Margin="200,112,0,0" TextWrapping="Wrap" Text="255.255.0.0" VerticalAlignment="Top" Width="125" Background="#FF$TextBoxBackColor" Foreground="#FF$TextBoxForeColor"/>
        <TextBox Name="CIDR" HorizontalAlignment="Left" Height="20" Margin="350,112,0,0" TextWrapping="Wrap" Text="16" VerticalAlignment="Top" Width="75" Background="#FF$TextBoxBackColor" Foreground="#FF$TextBoxForeColor"/>
        <TextBlock Name="networkLabel" HorizontalAlignment="Left" Margin="50,165,0,0" TextWrapping="Wrap" Text="Network" VerticalAlignment="Top"/>
        <TextBlock Name="NetworkID" HorizontalAlignment="Left" Margin="50,186,0,0" TextWrapping="Wrap" Text="Network" VerticalAlignment="Top" Width="125" Height="20" Background="#FF$TextBlockBackColor" TextAlignment="Center"/>
        <TextBlock Name="Wildcard" HorizontalAlignment="Left" Margin="200,186,0,0" TextWrapping="Wrap" Text="Network" VerticalAlignment="Top" Width="125" Height="20" Background="#FF$TextBlockBackColor" TextAlignment="Center"/>
        <TextBlock Name="Hosts" HorizontalAlignment="Left" Margin="350,186,0,0" TextWrapping="Wrap" Text="Network" VerticalAlignment="Top" Width="75" Height="20" Background="#FF$TextBlockBackColor" TextAlignment="Center"/>
        <TextBlock Name="WildcardMaskLabel" HorizontalAlignment="Left" Margin="200,165,0,0" TextWrapping="Wrap" Text="Wildcard Mask" VerticalAlignment="Top"/>
        <TextBlock Name="HostsLabel" HorizontalAlignment="Left" Margin="350,165,0,0" TextWrapping="Wrap" Text="Hosts" VerticalAlignment="Top"/>
        <TextBlock Name="BroadcastLabel" HorizontalAlignment="Left" Margin="50,229,0,0" TextWrapping="Wrap" Text="Broadcast Address" VerticalAlignment="Top"/>
        <TextBlock Name="Broadcast" HorizontalAlignment="Left" Margin="50,250,0,0" TextWrapping="Wrap" Text="Network" VerticalAlignment="Top" Width="125" Height="20" Background="#FF$TextBlockBackColor" TextAlignment="Center"/>
        <TextBlock Name="HostRangeLabel" HorizontalAlignment="Left" Margin="200,229,0,0" TextWrapping="Wrap" Text="Host Address Range" VerticalAlignment="Top"/>
        <TextBlock Name="HostRange" HorizontalAlignment="Left" Margin="200,250,0,0" TextWrapping="Wrap" Text="Network" VerticalAlignment="Top" Width="225" Height="20" Background="#FF$TextBlockBackColor" TextAlignment="Center"/>
        <Grid HorizontalAlignment="Left" Height="215" Margin="4,285,0,0" VerticalAlignment="Top" Width="466">
            <TextBlock Name="BinPanelLabel" HorizontalAlignment="Left" Margin="4,-4,0,0" TextWrapping="Wrap" Text="Binary" VerticalAlignment="Top" FontSize="22"/>
            <StackPanel Margin="146,0,0,0" Orientation="Vertical" Height="176" Width="275" HorizontalAlignment="Left">
                <TextBlock Name="BinaryAddress" HorizontalAlignment="Left" Margin="1,8,0,0" TextWrapping="Wrap" Text="Network" VerticalAlignment="Top" Width="275" Height="20" Background="#FF$TextBlockBackColor" TextAlignment="Center" FontFamily="Consolas" FontSize="15"/>
                <TextBlock Name="BinaryNetmask" HorizontalAlignment="Left" Margin="1,8,0,0" TextWrapping="Wrap" Text="Network" VerticalAlignment="Top" Width="275" Height="20" Background="#FF$TextBlockBackColor" TextAlignment="Center" FontFamily="Consolas" FontSize="15"/>
                <TextBlock Name="BinaryWildCard" HorizontalAlignment="Left" Margin="1,8,0,0" TextWrapping="Wrap" Text="Network" VerticalAlignment="Top" Width="275" Height="20" Background="#FF$TextBlockBackColor" TextAlignment="Center" FontFamily="Consolas" FontSize="15"/>
                <TextBlock Name="BinaryHostMin" HorizontalAlignment="Left" Margin="1,8,0,0" TextWrapping="Wrap" Text="Network" VerticalAlignment="Top" Width="275" Height="20" Background="#FF$TextBlockBackColor" TextAlignment="Center" FontFamily="Consolas" FontSize="15"/>
                <TextBlock Name="BinaryHostMax" HorizontalAlignment="Left" TextWrapping="Wrap" Text="Network" VerticalAlignment="Top" Width="276" Height="20" Background="#FF$TextBlockBackColor" TextAlignment="Center" Margin="0,8,0,0" FontFamily="Consolas" FontSize="15"/>
                <TextBlock Name="BinaryBroadcast" HorizontalAlignment="Left" Margin="0,8,0,0" TextWrapping="Wrap" Text="Network" VerticalAlignment="Top" Width="275" Height="20" Background="#FF$TextBlockBackColor" TextAlignment="Center" FontFamily="Consolas" FontSize="15"/>
            </StackPanel>
            <TextBlock Name="BinIPLabel" HorizontalAlignment="Right" Margin="0,28,325,0" TextWrapping="Wrap" Text="IP Address" VerticalAlignment="Top" TextAlignment="Right"/>
            <TextBlock Name="BinMaskLabel" HorizontalAlignment="Right" Margin="0,56,325,0" TextWrapping="Wrap" Text="Netmask" VerticalAlignment="Top" TextAlignment="Right"/>
            <TextBlock Name="BinWildCardLabel" HorizontalAlignment="Right" Margin="0,84,325,0" TextWrapping="Wrap" Text="Wildcard" VerticalAlignment="Top" TextAlignment="Right"/>
            <TextBlock Name="BinFirstLabel" HorizontalAlignment="Right" Margin="0,112,325,0" TextWrapping="Wrap" Text="First Address" VerticalAlignment="Top" TextAlignment="Right"/>
            <TextBlock Name="BinLastLabel" HorizontalAlignment="Right" Margin="0,140,325,0" TextWrapping="Wrap" Text="Last Address" VerticalAlignment="Top" TextAlignment="Right"/>
            <TextBlock Name="BinBroadcastLabel" HorizontalAlignment="Right" Margin="0,168,325,0" TextWrapping="Wrap" Text="Broadcast" VerticalAlignment="Top" TextAlignment="Right"/>
        </Grid>
        <Button Name="CloseButton" Content="Close" HorizontalAlignment="Center" Margin="200,521,200,0" Padding="8,4" VerticalAlignment="Top" Background="#FF$ButtonBackColor" Foreground="#FF$FormForeColor" BorderThickness="2" BorderBrush="#FF$FormForeColor"/>
        <TextBlock Name="ContosoLabel" HorizontalAlignment="Right" Margin="0,0,10,8" TextWrapping="Wrap" Text="Contoso.com" VerticalAlignment="Bottom" Foreground="#FF57B1FD"/>
    </Grid>
</Window>
"@

$WPFXamL = $WPFXamL -replace 'CONTOSO', "$company"
# Build Dialog
$WPFGui = New-WPFDialog -XamlData $WPFXaml

Function Fill-Form {
    param([switch]$IPChanged,
        [switch]$SubnetChanged,
        [Switch]$MaskChanged)
    if ( Validate-IP -IP $WPFGui.IPAddress.Text) {
        $WPFGui.IPAddress.Foreground = "#FF$TextBoxForeColor"
        if ( Validate-IP -IP $WPFGui.Subnet.Text) {
            $WPFGui.Subnet.Foreground = "#FF$TextBoxForeColor"
            $MaskBits = [int] $WPFGui.CIDR.Text
            if ( (1 -le $MaskBits) -and ( 255 -ge $MaskBits)) {
                $WPFGui.CIDR.Foreground = "#FF$TextBoxForeColor"
                $WPFGui.BinaryAddress.Text = ConvertTo-BinaryIP -IPV4Address $WPFGui.IPAddress.Text
                if ( $MaskChanged ) {
                    $WPFGui.BinaryNetmask.Text = ConvertTo-BinaryMask -MaskBits $WPFGui.CIDR.Text
                    $WPFGui.Subnet.Text = ConvertTo-IPString $WPFGui.BinaryNetMask.Text
                }
                elseif ( $SubnetChanged ) {
                    $WPFGui.BinaryNetmask.Text = ConvertTo-BinaryIP -IPV4Address $WPFGui.Subnet.Text
                    $WPFGui.CIDR.Text = $WPFGui.BinaryNetmask.Text.LastIndexOf('1') + 1

                }
                else {
                    $WPFGui.BinaryNetmask.Text = ConvertTo-BinaryIP -IPV4Address $WPFGui.Subnet.Text
                }

                $WPFGui.Hosts.Text = [System.Math]::Pow(2, (32 - $WPFGui.CIDR.Text)) - 2
                $BinaryNetwork = Band-IPStrings -Left $WPFGui.BinaryAddress.Text -Right $WPFGui.BinaryNetmask.Text
                $WPFGui.NetworkID.Text = ConvertTo-IPString -BinaryIPStr $BinaryNetwork
                $WPFGui.BinaryWildCard.Text = Get-NotIPString -BinString $WPFGui.BinaryNetmask.Text
                $WPFGui.Wildcard.Text = ConvertTo-IPString -BinaryIPStr $WPFGui.BinaryWildCard.Text
                $WPFGui.BinaryBroadcast.Text = Bor-IPStrings -Left $BinaryNetwork -Right $WPFGui.BinaryWildcard.Text
                $WPFGui.Broadcast.Text = ConvertTo-IPString -BinaryIPStr $WPFGui.BinaryBroadcast.Text
                $IPV4NetworkID = ([System.Net.IPAddress] $WPFGui.NetworkID.Text).GetAddressBytes()
                if ( 254 -gt $IPV4NetworkID[3]) {
                    $IPV4NetworkID[3] = $IPV4NetworkID[3] + 1
                }
                $FirstHost = $IPV4NetworkID -join '.'
                $WPFGui.BinaryHostMin.Text = ConvertTo-BinaryIP -IPV4Address $FirstHost

                $IPV4Broadcast = ([System.Net.IPAddress] $WPFGui.Broadcast.Text).GetAddressBytes()
                if ( 1 -lt $IPV4BroadCast[3] ) {
                    $IPV4Broadcast[3] = $IPV4Broadcast[3] - 1
                }
                $LastHost = $IPV4Broadcast -join '.'
                $WPFGui.BinaryHostMax.Text = ConvertTo-BinaryIP -IPV4Address $LastHost

                $WPFGui.HostRange.Text = "$FirstHost - $LastHost"
            }
            else {
                $WPFGui.CIDR.Foreground = "#FFFF0000"
            }
        }
        else {
            $WPFGui.Subnet.Foreground = "#FFFF0000"
        }
    }
    else {
        $WPFGui.IPAddress.Foreground = "#FFFF0000"
    }
}
$WPFGui.CloseButton.Add_Click( {
        $WPFGui.UI.Close()
    })

$WPFGui.IPAddress.Add_LostFocus( {
        Fill-Form -IPChanged
    })

$WPFGui.Subnet.Add_LostFocus( {
        Fill-Form -SubnetChanged
    })

$WPFGui.CIDR.Add_LostFocus( {
        Fill-Form -MaskChanged
    })
#endregion

$FavIcon = Test-Path -Path "C:\temp\deployment\core.ico" -PathType Leaf
If ($FavIcon -eq $false) {
    Invoke-WebRequest "https://www.dropbox.com/s/k4yc71klmxj63mj/core.ico?dl=1#" -OutFile "C:\temp\deployment\core.ico"
}
$WPFGui.RootWindow.Icon = 'C:\temp\deployment\core.ico'

Fill-Form
$null = $WPFGUI.UI.Dispatcher.InvokeAsync{ $WPFGui.UI.ShowDialog() }.Wait()