###############################################################################
# OpenVAS Vulnerability Test
#
# VMware Products Multiple Vulnerabilities (Windows) - jun 11
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801948");
  script_version("2020-05-15T08:09:24+0000");
  script_tag(name:"last_modification", value:"2020-05-15 08:09:24 +0000 (Fri, 15 May 2020)");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_cve_id("CVE-2011-1787", "CVE-2011-2146");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VMware Products Multiple Vulnerabilities (Windows) - jun 11");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2011-0009.html");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2011/000141.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to gain privileges on the guest OS.");

  script_tag(name:"affected", value:"VMware Player 3.1.x before 3.1.4

  VMware Workstation 7.1.x before 7.1.4 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An information disclosure vulnerability in 'Mount.vmhgfs', allows guest OS
    users to determine the existence of host OS files and directories via
    unspecified vectors.

  - A race condition privilege escalation in 'Mount.vmhgfs' via a race condition,
    that allows guest OS users to gain privileges on the guest OS by mounting a
    file system on top of an arbitrary directory.");

  script_tag(name:"summary", value:"The host is installed with VMWare product(s) which are vulnerable
  to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Apply the patch or upgrade to player 3.1.4 or later.

  Apply the patch or upgrade to VMware Workstation 7.1.4 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list( "cpe:/a:vmware:player", "cpe:/a:vmware:workstation" );

if( ! infos = get_app_version_and_location_from_list( cpe_list:cpe_list, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if( "cpe:/a:vmware:player" >< cpe ) {
  if( version_in_range( version: vers, test_version: "3.1.0", test_version2: "3.1.3" ) ) {
    report = report_fixed_ver( installed_version: vers, fixed_version: "3.1.4", install_path: path );
    security_message( port: 0, data: report );
    exit( 0 );
  }
}

else if( "cpe:/a:vmware:workstation" >< cpe ) {
  if( version_in_range( version: vers, test_version: "7.1.0", test_version2: "7.1.3" ) ) {
    report = report_fixed_ver( installed_version: vers, fixed_version: "7.1.4", install_path: path );
    security_message(port: 0, data: report);
    exit( 0 );
  }
}

exit( 99 );
