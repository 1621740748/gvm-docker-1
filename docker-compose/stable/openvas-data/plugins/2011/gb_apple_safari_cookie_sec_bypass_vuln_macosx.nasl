###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari Secure Cookie Security Bypass Vulnerability (Mac OS X)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802238");
  script_version("2020-03-02T13:53:38+0000");
  script_tag(name:"last_modification", value:"2020-03-02 13:53:38 +0000 (Mon, 02 Mar 2020)");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_cve_id("CVE-2008-7296");
  script_bugtraq_id(49136);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Apple Safari Secure Cookie Security Bypass Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://michael-coates.blogspot.com/2010/01/cookie-forcing-trust-your-cookies-no.html");
  script_xref(name:"URL", value:"http://scarybeastsecurity.blogspot.com/2011/02/some-less-obvious-benefits-of-hsts.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to overwrite or
  delete arbitrary cookies by sending a specially crafted HTTP response through
  a man-in-the-middle attack.");

  script_tag(name:"affected", value:"Apple Safari versions 5.1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to lack of the HTTP Strict Transport Security
  (HSTS) includeSubDomains feature, which allows man-in-the-middle attackers to
  overwrite or delete arbitrary cookies via a Set-Cookie header in an HTTP response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is installed with Apple Safari web browser and is prone
  to security bypass vulnerability.");

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

if(version_is_less_equal(version:vers, test_version:"5.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
