###############################################################################
# OpenVAS Vulnerability Test
#
# PhotoPost PHP 'showgallery.php' Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103104");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-03-03 13:33:12 +0100 (Thu, 03 Mar 2011)");
  script_bugtraq_id(46649);
  script_cve_id("CVE-2005-0274");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("PhotoPost PHP 'showgallery.php' Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46649");
  script_xref(name:"URL", value:"http://www.photopost.com");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/516793");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("photopost_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("photopost/detected");

  script_tag(name:"summary", value:"PhotoPost PHP is prone to multiple cross-site scripting
  vulnerabilities because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may let the attacker steal cookie-based authentication
  credentials and launch other attacks.");

  script_tag(name:"affected", value:"PhotoPost PHP 4.8c is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(!dir = get_dir_from_kb(port:port,app:"photopost"))exit(0);

url = string(dir, '/showgallery.php?si="<script>alert(/vt-xss-test/)</script>"');

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/vt-xss-test/\)</script>", check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
