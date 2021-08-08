# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106626");
  script_cve_id("CVE-2016-9221");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2021-06-01T08:15:37+0000");

  script_name("Cisco Mobility Express 2800 and 3800 802.11 Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170118-cme2");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in 802.11 ingress connection authentication handling for the
Cisco Mobility Express 2800 and 3800 Access Points could allow an unauthenticated, adjacent attacker to cause
authentication to fail.");

  script_tag(name:"insight", value:"The vulnerability is due to improper error handling for 802.11 authentication
requests that do not complete. An attacker could exploit this vulnerability by sending a crafted 802.11 frame to
the targeted device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to impact the availability of the device
due to authentication failures.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2021-06-01 08:15:37 +0000 (Tue, 01 Jun 2021)");
  script_tag(name:"creation_date", value:"2017-03-02 11:11:21 +0700 (Thu, 02 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_wlc_consolidation.nasl");
  script_mandatory_keys("cisco/wlc/detected", "cisco/wlc/model");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("cisco/wlc/model");
if (!model || model !~ "^AIR-AP(2|3)8[0-9]{2}")
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

affected = make_list("8.2.121.12",
                     "8.4.1.82");

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
