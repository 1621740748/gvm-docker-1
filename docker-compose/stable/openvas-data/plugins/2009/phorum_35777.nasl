###############################################################################
# OpenVAS Vulnerability Test
#
# Phorum Multiple BBCode HTML Injection Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100248");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
  script_bugtraq_id(35777);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Phorum Multiple BBCode HTML Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35777");
  script_xref(name:"URL", value:"http://www.phorum.org/");
  script_xref(name:"URL", value:"http://www.phorum.org/phorum5/read.php?64,139411");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/505186");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("phorum_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phorum/detected");

  script_tag(name:"solution", value:"Vendor fixes are available. Please see the references for details.");

  script_tag(name:"summary", value:"Phorum is prone to multiple HTML-injection vulnerabilities because it
  fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"Attacker-supplied HTML or JavaScript code could run in the context of
  the affected site, potentially allowing the attacker to steal cookie-
  based authentication credentials and to control how the site is
  rendered to the user, other attacks are also possible.");

  script_tag(name:"affected", value:"Versions prior to Phorum 5.2.12a are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);
if(!version = get_kb_item(string("www/", port, "/phorum")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {
  if(version_is_less(version: vers, test_version: "5.2.12a")) {
    security_message(port:port, data:"The target host was found to be vulnerable.");
    exit(0);
  }
}

exit(99);
