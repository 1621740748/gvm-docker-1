# Copyright (C) 2010 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.801336");
  script_version("2020-08-17T11:25:37+0000");
  script_tag(name:"last_modification", value:"2020-08-17 11:25:37 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1869", "CVE-2010-1628");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Ghostscript Parser Buffer Overflow Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/393809.php");
  script_xref(name:"URL", value:"http://www.checkpoint.com/defense/advisories/public/2010/cpai-10-May.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_ghostscript_detect_win.nasl");
  script_mandatory_keys("artifex/ghostscript/win/detected");
  script_tag(name:"impact", value:"Successful exploitation allows the attacker to execute arbitrary
code in the context of the affected application and can cause denial of service.");
  script_tag(name:"affected", value:"Ghostscript version 8.70 and 8.64 on Windows.");
  script_tag(name:"insight", value:"These flaws are due to,

  - Boundary error in the 'parser()' which allows the attackers to
execute arbitrary code via a crafted PostScript file.

  - Buffer overflow and memory corruption errors when processing a recursive
procedure invocations, which could be exploited to crash an affected
application or execute arbitrary code.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Ghostscript and is prone to
Buffer Overflow Vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

CPE = "cpe:/a:artifex:ghostscript";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "8.0", test_version2: "8.70" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
