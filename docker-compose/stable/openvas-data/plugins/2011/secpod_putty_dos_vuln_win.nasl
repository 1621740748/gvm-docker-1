# Copyright (C) 2011 SecPod
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

CPE = "cpe:/a:putty:putty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902780");
  script_version("2021-06-01T06:37:42+0000");
  script_tag(name:"last_modification", value:"2021-06-01 06:37:42 +0000 (Tue, 01 Jun 2021)");
  script_tag(name:"creation_date", value:"2011-12-26 18:52:49 +0530 (Mon, 26 Dec 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("PuTTY DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_putty_portable_detect.nasl");
  script_mandatory_keys("putty/detected");

  script_tag(name:"summary", value:"PuTTY is prone to denial of service (DoS) vulnerability.");
  script_tag(name:"insight", value:"The flaw is caused to unspecified error in the application.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a DoS.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PuTTY version 0.60");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18270/");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/108151/Putty-0.60-Denial-Of-Service.html");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_equal( version:version, test_version:"0.60" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
