# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107735");
  script_version("2019-11-01T07:56:07+0000");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-11-01 07:56:07 +0000 (Fri, 01 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-10-25 09:53:31 +0200 (Fri, 25 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-3982");

  script_name("Tenable Nessus <= 8.7.0 Denial of Service Vulnerability (TNS-2019-06)");

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");

  script_tag(name:"summary", value:"This host is running Tenable Nessus and is prone to
  a denial of service vulnerability due to improper validation of specific imported scan types.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An authenticated, remote attacker could potentially exploit this
  vulnerability to create a denial of service condition.");

  script_tag(name:"affected", value:"Tenable Nessus through version 8.6.0.");

  script_tag(name:"solution", value:"Upgrade to Tenable Nessus version 8.7.0 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2019-06");

  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"8.7.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.7.0", install_path:path );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
