###############################################################################
# OpenVAS Vulnerability Test
#
# OpenSSH UseLogin Environment Variables
#
# Authors:
# EMAZE Networks S.p.A.
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
# changes by rd: description, static report
#
# Copyright:
# Copyright (C) 2001 EMAZE Networks S.p.A.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10823");
  script_version("2019-09-07T11:55:45+0000");
  script_tag(name:"last_modification", value:"2019-09-07 11:55:45 +0000 (Sat, 07 Sep 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3614);
  script_xref(name:"IAVA", value:"2001-t-0017");
  script_cve_id("CVE-2001-0872");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("OpenSSH UseLogin Environment Variables");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is copyright (C) 2001 by EMAZE Networks S.p.A.");
  script_family("Gain a shell remotely");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"solution", value:"Upgrade to OpenSSH 3.0.2 or apply the patch for prior
  versions.");

  script_tag(name:"summary", value:"You are running a version of OpenSSH which is older than 3.0.2.");

  script_tag(name:"insight", value:"Versions prior than 3.0.2 are vulnerable to an environment variables
  export that can allow a local user to execute command with root privileges.");

  script_tag(name:"affected", value:"This problem affect only versions prior than 3.0.2, and when
  the UseLogin feature is enabled (usually disabled by default).");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"3.0.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
