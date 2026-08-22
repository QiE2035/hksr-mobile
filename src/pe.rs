use anyhow::{bail, Result};
use std::fmt;

/// PE 节区信息
pub struct Section {
    pub name: [u8; 8],
    pub rva: usize,
    pub virtual_size: usize,
}

impl Section {
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&c| c == 0).unwrap_or(8);
        std::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (RVA=0x{:X}, Size=0x{:X})",
            self.name_str(),
            self.rva,
            self.virtual_size
        )
    }
}

/// PE 头解析结果
pub struct PeHeader {
    pub size_of_image: usize,
    pub sections: Vec<Section>,
}

/// 从远程进程读取的 PE 头数据（0x1000 字节）中解析关键信息
pub fn parse(header_data: &[u8]) -> Result<PeHeader> {
    if header_data.len() < 0x40 {
        bail!("PE 头太小");
    }

    let e_lfanew = u32::from_le_bytes(header_data[0x3C..0x40].try_into().unwrap()) as usize;

    if header_data.len() < e_lfanew + 4 || &header_data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        bail!("无效的 PE 签名");
    }

    let num_sections =
        u16::from_le_bytes(header_data[e_lfanew + 6..e_lfanew + 8].try_into().unwrap()) as usize;

    let opt_off = e_lfanew + 24;
    let magic = u16::from_le_bytes(
        header_data[opt_off..opt_off + 2]
            .try_into()
            .unwrap(),
    );

    let size_of_image = u32::from_le_bytes(
        header_data[opt_off + 56..opt_off + 60]
            .try_into()
            .unwrap(),
    ) as usize;

    let section_table_off = match magic {
        0x20b => opt_off + 240, // PE32+ (64-bit)
        0x10b => opt_off + 224, // PE32 (32-bit)
        _ => bail!("未知的 Optional Header magic: 0x{:04X}", magic),
    };

    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let off = section_table_off + i * 40;
        if off + 40 > header_data.len() {
            break;
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&header_data[off..off + 8]);
        let rva =
            u32::from_le_bytes(header_data[off + 12..off + 16].try_into().unwrap()) as usize;
        let virtual_size =
            u32::from_le_bytes(header_data[off + 8..off + 12].try_into().unwrap()) as usize;
        sections.push(Section {
            name,
            rva,
            virtual_size,
        });
    }

    Ok(PeHeader {
        size_of_image,
        sections,
    })
}
