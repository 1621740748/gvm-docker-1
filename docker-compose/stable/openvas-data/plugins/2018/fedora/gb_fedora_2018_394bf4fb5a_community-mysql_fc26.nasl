###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for community-mysql FEDORA-2018-394bf4fb5a
#
# Authors:
# System Generated Check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.874194");
  script_version("2021-06-11T11:00:20+0000");
  script_tag(name:"last_modification", value:"2021-06-11 11:00:20 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-03-14 08:38:12 +0100 (Wed, 14 Mar 2018)");
  script_cve_id("CVE-2018-2696", "CVE-2018-2703", "CVE-2018-2565", "CVE-2018-2573",
                "CVE-2018-2576", "CVE-2018-2583", "CVE-2018-2586", "CVE-2018-2590",
                "CVE-2018-2600", "CVE-2018-2612", "CVE-2018-2622", "CVE-2018-2640",
                "CVE-2018-2645", "CVE-2018-2646", "CVE-2018-2647", "CVE-2018-2665",
                "CVE-2018-2667", "CVE-2018-2668");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-28 01:29:00 +0000 (Wed, 28 Mar 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for community-mysql FEDORA-2018-394bf4fb5a");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'community-mysql'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"community-mysql on Fedora 26");
  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"FEDORA", value:"2018-394bf4fb5a");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2XVKEO4WIUCUUOFMMGSFVRPB62HV2HWZ");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC26");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"community-mysql", rpm:"community-mysql~5.7.21~6.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
