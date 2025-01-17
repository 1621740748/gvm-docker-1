###############################################################################
# OpenVAS Vulnerability Test
#
# AWStats Multiple Unspecified Security Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:awstats:awstats";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100380");
  script_version("2020-10-20T15:03:35+0000");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2009-12-08 22:02:24 +0100 (Tue, 08 Dec 2009)");
  script_bugtraq_id(37157);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("AWStats Multiple Unspecified Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37157");
  script_xref(name:"URL", value:"http://awstats.sourceforge.net/docs/awstats_changelog.txt");

  script_category(ACT_GATHER_INFO);

  script_tag(name:"qod_type", value:"remote_banner");

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("awstats_detect.nasl");
  script_mandatory_keys("awstats/installed");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"AWStats is prone to multiple security vulnerabilities.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: vers, test_version: "6.95")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "6.95");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
