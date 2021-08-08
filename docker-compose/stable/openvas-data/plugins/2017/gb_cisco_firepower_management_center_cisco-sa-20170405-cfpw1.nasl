###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Firepower Detection Engine SSL Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:cisco:firepower_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106816");
  script_cve_id("CVE-2017-3887");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_version("2020-04-03T09:54:35+0000");

  script_name("Cisco Firepower Detection Engine SSL Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-cfpw1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the detection engine that handles Secure Sockets Layer
  (SSL) packets for Cisco Firepower System Software could allow an unauthenticated, remote attacker to cause a
  denial of service (DoS) condition because the Snort process unexpectedly restarts.");

  script_tag(name:"insight", value:"The vulnerability is due to improper error handling of an SSL packet in an
  established SSL connection. An attacker could exploit this vulnerability by sending a crafted SSL packet stream
  to the detection engine on the targeted device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause a DoS condition if the Snort
  process restarts, causing traffic inspection to be bypassed or traffic to be dropped.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2020-04-03 09:54:35 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2017-05-18 13:56:09 +0700 (Thu, 18 May 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_firepower_management_center_consolidation.nasl");
  script_mandatory_keys("cisco/firepower_management_center/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

affected = make_list(
  '6.0.1',
  '6.1.0',
  '6.2.0');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
