# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150695");
  script_version("2021-06-22T12:50:16+0000");
  script_tag(name:"last_modification", value:"2021-06-22 12:50:16 +0000 (Tue, 22 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-21 09:34:21 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-18 00:00:00 +0000 (Thu, 18 Jun 2020)");

  script_cve_id("CVE-2004-0657");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NTP < 4.0 Integer Overflow or Wraparound Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_tag(name:"summary", value:"Integer overflow in the NTP daemon (NTPd) before 4.0 causes the
  NTP server to return the wrong date/time offset when a client requests a date/time that is more
  than 34 years away from the server's time.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"affected", value:"NTPd version prior to 4.0.");

  script_tag(name:"solution", value:"Update to version 4.0 or later.");

  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#July_1999_Internal_overflow_if_d");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"4.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.0", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
