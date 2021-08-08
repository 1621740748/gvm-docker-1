###############################################################################
# OpenVAS Vulnerability Test
#
# Apache TomEE console (tomee-webapp) Cross Site Scripting Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:tomee";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813736");
  script_version("2021-06-15T02:00:29+0000");
  script_tag(name:"last_modification", value:"2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-07-31 09:20:00 +0530 (Tue, 31 Jul 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-28 22:06:00 +0000 (Thu, 28 Feb 2019)");

  script_cve_id("CVE-2018-8031");

  ## unreliable installation via tomee-webapp are vulnerable
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache TomEE console (tomee-webapp) XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomee_server_detect.nasl");
  script_mandatory_keys("apache/tomee/detected");

  script_tag(name:"summary", value:"Apache TomEE is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified error in
  the 'tomee-webapp' web application which is typically used to add TomEE features
  to a Tomcat installation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct Cross Site Scripting attacks.");

  script_tag(name:"affected", value:"Apache TomEE console (tomee-webapp)");

  script_tag(name:"solution", value:"Removing the application after TomEE is setup
  (if using the application to install TomEE) or use one of the provided
  pre-configured installation bundles or upgrade to TomEE 7.0.5.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/c4b0d83a534d6cdf2de54dbbd00e3538072ac2e360781b784608ed0d@%3Cdev.tomee.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version:version, test_version:"7.0.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"7.0.5", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
