###############################################################################
# OpenVAS Vulnerability Test
#
# NETGEAR DGN2200 CVE-2017-6334 Remote Code Execution Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107229");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"last_modification", value:"2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)");
  script_tag(name:"creation_date", value:"2017-06-28 17:33:05 +0200 (Wed, 28 Jun 2017)");
  script_cve_id("CVE-2017-6334");

  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NETGEAR DGN2200 CVE-2017-6334 Remote Code Execution Vulnerability");

  script_tag(name:"summary", value:"NETGEAR DGN2200 is prone to a remote code-execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code within the context of the affected application. Failed exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"NETGEAR DGN2200 v1, v2, v3, v4");

  script_tag(name:"solution", value:"Update the Firmware, for more details");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96463");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  # This script was deprecated to avoid false positive, since the firmware version could not be obtained without authentication.
  script_tag(name:"deprecated", value:TRUE);

  script_xref(name:"URL", value:"https://kb.netgear.com/000037343/Security-Advisory-for-Remote-Command-Execution-and-CSRF-Vulnerabilities-on-DGN2200");
  exit(0);
}

exit(66);
