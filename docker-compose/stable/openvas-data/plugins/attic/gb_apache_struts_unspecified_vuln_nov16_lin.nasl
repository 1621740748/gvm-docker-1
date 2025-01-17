# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809475");
  script_version("2021-03-31T14:01:21+0000");
  script_cve_id("CVE-2016-4436");
  script_bugtraq_id(91280);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-31 14:01:21 +0000 (Wed, 31 Mar 2021)");
  script_tag(name:"creation_date", value:"2016-11-18 14:16:36 +0530 (Fri, 18 Nov 2016)");
  script_name("Apache Struts Unspecified Vulnerability (S2-035) - Linux");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-035");

  script_tag(name:"summary", value:"Apache Struts is prone to an unspecified
  vulnerability.

  This VT has been merged into the VT 'Apache Struts Unspecified Vulnerability (S2-035)'
  (OID: 1.3.6.1.4.1.25623.1.0.809474).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The flaw exists due to the method used to clean up
  action name can produce vulnerable payload based on crafted input.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass
  certain security restrictions and perform unauthorized actions. This may lead to further
  attacks.");

  script_tag(name:"affected", value:"Apache Struts 2.x through 2.3.29 and 2.5.0.");

  script_tag(name:"solution", value:"Update to version 2.3.29, 2.5.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);