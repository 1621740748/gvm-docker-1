###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle WebLogic Server Node Manager 'beasvc.exe' Remote Command Execution Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:bea:weblogic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100494");
  script_version("2021-05-10T09:07:58+0000");
  script_tag(name:"last_modification", value:"2021-05-10 09:07:58 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2010-02-14 12:35:00 +0100 (Sun, 14 Feb 2010)");
  script_bugtraq_id(37926);
  script_cve_id("CVE-2010-0073");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle WebLogic Server Node Manager 'beasvc.exe' Remote Command Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37926");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/oracle-weblogic-1032-node-manager-fun.html");
  script_xref(name:"URL", value:"http://blogs.oracle.com/security/2010/02/security_alert_for_cve-2010-00.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technology/deploy/security/alerts/alert-cve-2010-0073.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_oracle_weblogic_consolidation.nasl");
  script_mandatory_keys("oracle/weblogic/detected");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the vendor advisory for details.");

  script_tag(name:"summary", value:"Oracle WebLogic Server is prone to a remote command-execution vulnerability
  because the software fails to restrict access to sensitive commands.

  Successful attacks can compromise the affected software and possibly the computer.

  Oracle WebLogic Server 10.3.2 is vulnerable, other versions may also be affected.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "10.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See reference");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
