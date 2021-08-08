# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/h:fortinet:fortigate";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105727");
  script_cve_id("CVE-2015-5738");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2021-07-12T08:06:48+0000");

  script_name("Fortinet FortiGate RSA-CRT Key Leak (FG-IR-16-008)");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-16-008");

  script_tag(name:"impact", value:"Man in the middle");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to FortiOS 5.0.13 / 5.2.6 / 5.4.0 or newer");

  script_tag(name:"summary", value:"FortiOS now includes for all SSL libraries a countermeasure against Lenstra's fault attack on RSA-CRT optimization when a RSA signature is corrupted.");

  script_tag(name:"affected", value:"FortiGate <  5.0.13 / 5.2.6 / 5.4.0 with the SSLVPN web portal feature configured.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2021-07-12 08:06:48 +0000 (Mon, 12 Jul 2021)");
  script_tag(name:"creation_date", value:"2016-05-18 13:18:29 +0200 (Wed, 18 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_fortigate_version.nasl");
  script_mandatory_keys("fortigate/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version =~ "^5\.0" ) fix = '5.0.13';
if( version =~ "^5\.2" ) fix = '5.2.6';
if( version =~ "^5\.3" ) fix = '5.4.0';

if( ! fix ) exit( 0 );

if( version_is_less( version:version, test_version:fix ) )
{
  model = get_kb_item("fortigate/model");
  if( ! isnull( model ) ) report = 'Model:             ' + model + '\n';
  report += 'Installed Version: ' + version + '\nFixed Version:     ' + fix + '\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );