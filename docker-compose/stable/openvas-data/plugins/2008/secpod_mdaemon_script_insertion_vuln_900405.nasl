#############################################################################
# OpenVAS Vulnerability Test
#
# MDaemon Server WordClient Script Insertion Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

CPE = "cpe:/a:alt-n:mdaemon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900405");
  script_version("2021-02-08T15:30:09+0000");
  script_tag(name:"last_modification", value:"2021-02-08 15:30:09 +0000 (Mon, 08 Feb 2021)");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-6967");
  script_bugtraq_id(32355);
  script_copyright("Copyright (C) 2008 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_name("MDaemon Server WordClient Script Insertion Vulnerability");
  script_dependencies("gb_altn_mdaemon_consolidation.nasl");
  script_mandatory_keys("altn/mdaemon/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32142");
  script_xref(name:"URL", value:"http://files.altn.com/MDaemon/Release/RelNotes_en.txt");

  script_tag(name:"impact", value:"An attacker can execute malicious arbitrary code in the email body.");

  script_tag(name:"affected", value:"MDaemon Server version prior to 10.0.2.");

  script_tag(name:"insight", value:"This vulnerability is due to an input validation error in 'HTML tags' in
  emails which are not properly filtered before displaying. This can be exploited when the malicious email is viewed.");

  script_tag(name:"solution", value:"Update to version 10.0.2 or later.");

  script_tag(name:"summary", value:"MDaemon is prone to a script insertion vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "10.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version:"10.0.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
