# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107317");
  script_version("2021-06-23T06:26:38+0000");
  script_tag(name:"last_modification", value:"2021-06-23 06:26:38 +0000 (Wed, 23 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-04-23 13:53:08 +0200 (Mon, 23 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("7zip Portable Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  # nb: 7zip dependency was added so we don't detect a registry-based installation twice
  script_dependencies("gb_7zip_detect_win.nasl", "gb_wmi_access.nasl", "lsc_options.nasl");
  script_mandatory_keys("win/lsc/search_portable_apps", "WMI/access_successful");
  script_exclude_keys("win/lsc/disable_wmi_search");

  script_tag(name:"summary", value:"SMB login and WMI file search based detection of 7zip Portable.");

  script_tag(name:"insight", value:"To enable the search for portable versions of this product you
  need to 'Enable Detection of Portable Apps on Windows' in the 'Options for Local Security Checks'
  (OID: 1.3.6.1.4.1.25623.1.0.100509) of your scan config.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("wmi_file.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");

if( get_kb_item( "win/lsc/disable_wmi_search" ) )
  exit( 0 );

infos = kb_smb_wmi_connectinfo();
if( ! infos )
  exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle )
  exit( 0 );

fileList = wmi_file_fileversion( handle:handle, fileName:"7zFM", fileExtn:"exe", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

# From gb_7zip_detect_win.nasl to avoid a doubled detection of a registry-based installation.
detectedList = get_kb_list( "7zip/Win/InstallLocations" );

foreach filePath( keys( fileList ) ) {

  # wmi_file_fileversion returns the .exe filename so we're stripping it away
  # to keep the install location registration the same way like in gb_7zip_detect_win.nasl
  location = filePath - "\7zfm.exe";
  if( detectedList && in_array( search:tolower( location ), array:detectedList ) ) continue; # We already have detected this installation...

  vers = fileList[filePath];

  # Version of the 7zFM.exe file is something like 18.5.0.0
  # so we need to catch only the first three parts of the version.
  if( vers && version = eregmatch( string:vers, pattern:"^([0-9]+\.[0-9]+\.[0-9]+)" ) ) {

    set_kb_item( name:"7zip/Win/InstallLocations", value:tolower( location ) );

    # The portableapps.com installer is putting the 32bit version in App\7-Zip and the 64bit into App\7-Zip64.
    # This is the only way to differ between 32bit and 64bit as we can't differ between 32 and 64bit based on the file information.
    if( "7-zip64" >< location ) {
      cpe = "cpe:/a:7-zip:7-zip:x64";
      set_kb_item( name:"7zip64/Win/Ver", value:version[1] );
    } else {
      cpe = "cpe:/a:7-zip:7-zip";
      set_kb_item( name:"7zip/Win/Ver", value:version[1] );
    }
    register_and_report_cpe( app:"7-Zip Portable", ver:version[1], concluded:vers, base:cpe, expr:"^([0-9.]+)", insloc:location, regPort:0, regService:"smb-login" );
  }
}

exit( 0 );
