###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari Webcore Webkit 'XSSAuditor.cpp' XSS Vulnerability (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803108");
  script_version("2020-03-02T13:53:38+0000");
  script_cve_id("CVE-2012-5851");
  script_bugtraq_id(56570);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-03-02 13:53:38 +0000 (Mon, 02 Mar 2020)");
  script_tag(name:"creation_date", value:"2012-11-21 16:01:28 +0530 (Wed, 21 Nov 2012)");
  script_name("Apple Safari Webcore Webkit 'XSSAuditor.cpp' XSS Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"https://bugs.webkit.org/show_bug.cgi?id=92692");
  script_xref(name:"URL", value:"http://blog.opensecurityresearch.com/2012/09/simple-cross-site-scripting-vector-that.html");

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass a
  cross-site scripting (XSS) protection mechanism via a crafted string.");

  script_tag(name:"affected", value:"Apple Safari version 5.1.7 on Mac OS X.");

  script_tag(name:"insight", value:"The flaw is due to 'html/parser/XSSAuditor.cpp' in WebCore in
  WebKit does not consider all possible output contexts of reflected data.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with Apple Safari and is prone to cross
  site scripting vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"5.1.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
