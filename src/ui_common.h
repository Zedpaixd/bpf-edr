#ifndef EDR_UI_COMMON_H
#define EDR_UI_COMMON_H

#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/color.hpp>
#include <string>

namespace uic {

inline ftxui::Color risk_color(double r) {
    if (r < 0.20) return ftxui::Color::Green;
    if (r < 0.75) return ftxui::Color::Yellow;
    return ftxui::Color::Red;
}

inline std::string fmt_pct(double r) {
    char b[16];
    std::snprintf(b, sizeof(b), "%5.1f%%", r * 100.0);
    return b;
}

inline std::string hclip(const std::string &s, int off) {
    if (off <= 0) return s;
    if ((std::size_t)off >= s.size()) return std::string();
    return s.substr((std::size_t)off);
}

inline std::string short_hash(const std::string &h) {
    if (h.size() <= 12) return h;
    return h.substr(0, 12);
}

inline ftxui::Element wrap_indent(const std::string &s, int width, int indent,
                                  ftxui::Color c, bool bold_on) {
    using namespace ftxui;
    if (width < 8) width = 8;
    if (indent < 0) indent = 0;
    if (indent > width - 4) indent = width - 4;
    Elements lines;
    std::string pad(indent, ' ');
    std::size_t pos = 0;
    bool first = true;
    while (pos < s.size()) {
        int avail = first ? width : (width - indent);
        if (avail < 1) avail = 1;
        std::string chunk = s.substr(pos, (std::size_t)avail);
        pos += chunk.size();
        std::string full = first ? chunk : (pad + chunk);
        Element e = text(full) | color(c);
        if (bold_on) e = e | bold;
        lines.push_back(e);
        first = false;
    }
    if (lines.empty()) lines.push_back(text("") | color(c));
    return vbox(std::move(lines));
}

}

#endif