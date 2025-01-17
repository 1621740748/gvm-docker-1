###############################################################################
# OpenVAS Vulnerability Test
#
# Mahara Multiple Remote Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801889");
  script_version("2020-03-12T04:31:01+0000");
  script_tag(name:"last_modification", value:"2020-03-12 04:31:01 +0000 (Thu, 12 Mar 2020)");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_bugtraq_id(47798);
  script_cve_id("CVE-2011-1402", "CVE-2011-1403", "CVE-2011-1404", "CVE-2011-1405", "CVE-2011-1406");

  script_name("Mahara Multiple Remote Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44433");
  script_xref(name:"URL", value:"https://launchpad.net/mahara/+milestone/1.3.6");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mahara_detect.nasl");
  script_mandatory_keys("mahara/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site, steal cookie-based
  authentication credentials, disclose or modify sensitive information, or perform certain administrative actions
  and bypass security restrictions.");

  script_tag(name:"affected", value:"Mahara version prior to 1.3.6.");

  script_tag(name:"insight", value:"- An error in artefact/plans/viewtasks.json.php, artefact/blog/posts.json.php,
    and blocktype/myfriends/myfriends.json.php when checking a user's permission can be exploited to access
    restricted views.

  - An error in view/newviewtoken.json.php, artefact/plans/tasks.json.php, and artefact/blog/view/index.json.php
    when checking a user's permission can be exploited to edit restricted views.

  - An error in admin/users/search.json.php due to the 'INSTITUTIONALADMIN' permission not being checked can be
    exploited to search and suspend other users.

  - The application allows users to perform certain actions via HTTP requests without performing any validity
    checks to verify the requests. This can be exploited to create an arbitrary user with administrative
    privileges if a logged-in administrative user visits a malicious web site.

  - Input passed via certain email fields as a result of forum posts and view feedback notifications is not
    properly sanitised in artefact/comment/lib.php and interaction/forum/lib.php before being used.

  - Improper handling of an https URL in the wwwroot configuration setting, allows user-assisted remote attackers
    to obtain credentials by sniffing the network at a time when an http URL is used for a login.");

  script_tag(name:"solution", value:"Upgrade to Mahara version 1.3.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Mahara is prone to multiple remote vulnerabilities.");

  exit(0);
}

CPE = "cpe:/a:mahara:mahara";

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
