# Copyright (C) 2015 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805639");
  script_version("2021-07-12T08:06:48+0000");
  script_cve_id("CVE-2015-1880", "CVE-2014-8616");
  script_bugtraq_id(74652);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-07-12 08:06:48 +0000 (Mon, 12 Jul 2021)");
  script_tag(name:"creation_date", value:"2015-06-16 12:01:44 +0530 (Tue, 16 Jun 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fortinet FortiGate Reflected XSS Vulnerability (FG-IR-15-005)");

  script_tag(name:"summary", value:"Fortinet FortiGate is prone to a reflected cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the sslvpn login page
  does not validate input before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to create a specially crafted request that would
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"Fortinet FortiGate versions 5.2.x before
  5.2.3");

  script_tag(name:"solution", value:"Update to Fortinet FortiOS 5.2.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-15-005");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortigate_version.nasl");
  script_mandatory_keys("fortigate/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!fgVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:fgVer, test_version:"5.2.0", test_version2:"5.2.2"))
{
  report = 'Installed version: ' + fgVer + '\n' +
           'Fixed version:     ' + "5.2.3" + '\n';
  security_message(data:report);
  exit(0);
}
