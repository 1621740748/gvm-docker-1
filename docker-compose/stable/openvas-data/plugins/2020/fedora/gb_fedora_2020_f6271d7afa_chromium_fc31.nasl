# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.877601");
  script_version("2021-07-20T11:00:49+0000");
  script_cve_id("CVE-2019-20446", "CVE-2020-6381", "CVE-2020-6382", "CVE-2020-6383", "CVE-2020-6384", "CVE-2020-6385", "CVE-2020-6386", "CVE-2020-6387", "CVE-2020-6388", "CVE-2020-6389", "CVE-2020-6390", "CVE-2020-6391", "CVE-2020-6392", "CVE-2020-6393", "CVE-2020-6394", "CVE-2020-6395", "CVE-2020-6396", "CVE-2020-6397", "CVE-2020-6398", "CVE-2020-6399", "CVE-2020-6400", "CVE-2020-6401", "CVE-2020-6402", "CVE-2020-6403", "CVE-2020-6404", "CVE-2020-6405", "CVE-2020-6406", "CVE-2020-6407", "CVE-2020-6408", "CVE-2020-6409", "CVE-2020-6410", "CVE-2020-6411", "CVE-2020-6412", "CVE-2020-6413", "CVE-2020-6414", "CVE-2020-6415", "CVE-2020-6416", "CVE-2020-6417", "CVE-2020-6418", "CVE-2020-6420", "CVE-2020-10531");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-07-20 11:00:49 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-17 12:15:00 +0000 (Mon, 17 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-03-20 04:17:43 +0000 (Fri, 20 Mar 2020)");
  script_name("Fedora: Security Advisory for chromium (FEDORA-2020-f6271d7afa)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC31");

  script_xref(name:"FEDORA", value:"2020-f6271d7afa");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/X3B5RWJQD5LA45MYLLR55KZJOJ5NVZGP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2020-f6271d7afa advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium is an open-source web browser, powered by WebKit (Blink).");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 31.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC31") {

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~80.0.3987.132~1.fc31", rls:"FC31"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);