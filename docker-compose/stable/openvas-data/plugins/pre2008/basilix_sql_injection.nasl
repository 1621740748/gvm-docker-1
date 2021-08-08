# OpenVAS Vulnerability Test
# $Id: basilix_sql_injection.nasl 13975 2019-03-04 09:32:08Z cfischer $
# Description: BasiliX SQL Injection Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = "cpe:/a:basilix:basilix_webmail";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.14219");
  script_version("$Revision: 13975 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2002-1709");
  script_bugtraq_id(5061);

  script_name("BasiliX SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");

  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  script_dependencies("basilix_detect.nasl");
  script_mandatory_keys("basilix/installed");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to BasiliX version 1.1.1 or later.");

  script_tag(name:"summary", value:"The remote web server contains PHP scripts that are prone to SQL injection
attacks.

Description :

The remote host appears to be running a BasiliX version 1.1.0 or lower. Such versions are potentially vulnerable
to SQL injection attacks depending on the version of PHP installed.");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/vulnwatch/2002-q2/0117.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
