#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <input/input.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>
#include <toolbox/stream/file_stream.h>
#include <toolbox/stream/stream.h>
#include <furi_hal_nfc.h>
#include <furi/core/string.h>
#include <dialogs/dialogs.h>

#include <lib/nfc/nfc.h>
#include <lib/nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <lib/nfc/protocols/iso14443_3a/iso14443_3a_listener.h>
#include <lib/nfc/protocols/mf_ultralight/mf_ultralight.h>
#include <lib/nfc/protocols/mf_ultralight/mf_ultralight_listener.h>
#include <lib/nfc/protocols/mf_classic/mf_classic.h>
#include <lib/nfc/protocols/mf_classic/mf_classic_listener.h>
#include <nfc/nfc_listener.h>

#define TAG "AdvancedUID"

typedef enum {
    StateMenu,
    StateLoadFile,
    StateEditUID,
    StateSettings,
    StateRunning,
    StateAuto,
    StateFuzzer
} AppState;

typedef enum {
    MenuTechMifareClassic,
    MenuTechMifareUltralight,
    MenuTechNTAG213,
    MenuTechNTAG215,
    MenuTechNTAG216,
    MenuTechFelica,
    MenuTechIso15693,
    MenuLoadFile,
    MenuNum
} MenuOption;

typedef enum {
    TechMifareClassic,
    TechMifareUltralight,
    TechNTAG213,
    TechNTAG215,
    TechNTAG216,
    TechFelica,
    TechIso15693,
    TechNum
} NfcTechnology;

typedef enum {
    SettingsStep,
    SettingsOffset,
    SettingsLength,
    SettingsAutoDelay,
    SettingsFuzzerDelay,
    SettingsCount
} SettingsItem;

typedef struct {
    char uid[17];
    char edit_uid[17];
    char loaded_filename[64];
    uint8_t uid_len;
    uint32_t current_value;
    uint32_t max_value;
    uint32_t increment_step;
    uint8_t increment_offset;
    uint8_t increment_length;
    uint32_t auto_delay_ms;
    uint32_t fuzzer_delay_ms;
    uint32_t fuzzer_index;
    bool fuzzer_random_mode;
    bool file_loaded;
    NfcTechnology tech;
    AppState state;
    bool is_emulating;
    bool auto_mode;
    bool fuzzer_mode;
    bool uid_changed;
    
    Nfc* nfc;
    NfcListener* nfc_listener;
    Iso14443_3aData* iso14443_3a_data;
    MfUltralightData* mf_ultralight_data;
    MfClassicData* mf_classic_data;
    
    FuriThread* emulation_thread;
    FuriTimer* auto_timer;
    FuriTimer* fuzzer_timer;
    ViewPort* view_port;
    Gui* gui;
    FuriMessageQueue* event_queue;
    uint8_t menu_index;
    uint8_t menu_scroll_offset;
    uint8_t edit_position;
    uint8_t settings_index;
    uint8_t settings_scroll_offset;
    NotificationApp* notifications;
    DialogsApp* dialogs;
} AdvancedUidApp;

static const char* tech_names[TechNum] = {
    "Mifare Classic 1K",
    "Mifare Ultralight",
    "NTAG213",
    "NTAG215", 
    "NTAG216",
    "FeliCa",
    "ISO15693"
};

static const char* menu_names[MenuNum] = {
    "Mifare Classic 1K",
    "Mifare Ultralight",
    "NTAG213",
    "NTAG215", 
    "NTAG216",
    "FeliCa",
    "ISO15693",
    "Load NFC File"
};

static const uint16_t tech_atqa[TechNum] = {
    0x0004, 0x0044, 0x0044, 0x0044, 0x0044, 0x0344, 0x0044
};

static const uint8_t tech_sak[TechNum] = {
    0x08, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00
};

static const uint8_t tech_uid_sizes[TechNum] = {
    4, 7, 7, 7, 7, 8, 8
};

static const char* settings_names[SettingsCount] = {
    "Increment Step",
    "Offset Position", 
    "Increment Length",
    "Auto Delay (ms)",
    "Fuzzer Delay (ms)"
};

static const char* common_uids_4bytes[] = {
    "DEADBEEF", "CAFEBABE", "FEEDFACE", "BAADF00D", 
    "12345678", "ABCDEF00", "00000000", "FFFFFFFF"
};

static const char* common_uids_7bytes[] = {
    "04DEADBEEFCAFE", "04123456789ABC", "04ABCDEF012345",
    "04FEEDFACEBEEF", "04CAFEBABEF00D", "04BAADF00DCAFE"
};

static const char* common_uids_8bytes[] = {
    "DEADBEEFCAFEBABE", "FEEDFACEDEADBEEF", "BAADF00DCAFEBABE",
    "1234567890ABCDEF", "ABCDEF0123456789", "0123456789ABCDEF"
};

#define COMMON_UIDS_4BYTES_COUNT (sizeof(common_uids_4bytes) / sizeof(common_uids_4bytes[0]))
#define COMMON_UIDS_7BYTES_COUNT (sizeof(common_uids_7bytes) / sizeof(common_uids_7bytes[0]))
#define COMMON_UIDS_8BYTES_COUNT (sizeof(common_uids_8bytes) / sizeof(common_uids_8bytes[0]))

// Déclarations des fonctions
static void update_nfc_data(AdvancedUidApp* app);
static void auto_timer_callback(void* context);
static void fuzzer_timer_callback(void* context);
static int32_t nfc_emulation_thread(void* context);
static void start_emulation(AdvancedUidApp* app);
static void stop_emulation(AdvancedUidApp* app);
static void restart_emulation_if_needed(AdvancedUidApp* app);
static bool load_nfc_file(AdvancedUidApp* app);
static void draw_callback(Canvas* canvas, void* ctx);
static void input_callback(InputEvent* input_event, void* ctx);
static AdvancedUidApp* advanced_uid_app_alloc();
static void advanced_uid_app_free(AdvancedUidApp* app);

static uint8_t hex_char_to_value(char c) {
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

static void hex_string_to_bytes(const char* hex_str, uint8_t* bytes, uint8_t len) {
    size_t hex_len = strlen(hex_str);
    for(uint8_t i = 0; i < len; i++) {
        if((size_t)(i * 2 + 1) < hex_len) {
            bytes[i] = (hex_char_to_value(hex_str[i * 2]) << 4) | 
                       hex_char_to_value(hex_str[i * 2 + 1]);
        } else {
            bytes[i] = 0;
        }
    }
}

static void init_uid_for_tech(AdvancedUidApp* app) {
    app->uid_len = tech_uid_sizes[app->tech];
    
    switch(app->tech) {
        case TechMifareClassic:
            strcpy(app->uid, "DEADBEEF");
            app->increment_offset = 4;
            app->increment_length = 4;
            break;
        case TechMifareUltralight:
            strcpy(app->uid, "04123456789ABC");
            app->increment_offset = 10;
            app->increment_length = 4;
            break;
        case TechNTAG213:
            strcpy(app->uid, "04E10CDA993C80");
            app->increment_offset = 10;
            app->increment_length = 4;
            break;
        case TechNTAG215:
            strcpy(app->uid, "04E10CDA993C81");
            app->increment_offset = 10;
            app->increment_length = 4;
            break;
        case TechNTAG216:
            strcpy(app->uid, "04E10CDA993C82");
            app->increment_offset = 10;
            app->increment_length = 4;
            break;
        case TechFelica:
            strcpy(app->uid, "0123456789ABCDEF");
            app->increment_offset = 12;
            app->increment_length = 4;
            break;
        case TechIso15693:
            strcpy(app->uid, "E007000000123456");
            app->increment_offset = 12;
            app->increment_length = 4;
            break;
        default:
            strcpy(app->uid, "04123456789ABC");
            app->increment_offset = 10;
            app->increment_length = 4;
            break;
    }
    
    app->uid[app->uid_len * 2] = '\0';
    strcpy(app->edit_uid, app->uid);
    
    app->increment_step = 1;
    app->auto_delay_ms = 1000;
    app->fuzzer_delay_ms = 500;
    app->fuzzer_index = 0;
    app->fuzzer_random_mode = false;
    app->max_value = (1 << (app->increment_length * 4)) - 1;
    app->uid_changed = false;
    app->file_loaded = false;
    strcpy(app->loaded_filename, "");
    
    if(app->increment_offset + app->increment_length <= strlen(app->uid)) {
        unsigned int current_val = 0;
        char temp_str[9] = {0};
        strncpy(temp_str, &app->uid[app->increment_offset], app->increment_length);
        sscanf(temp_str, "%X", &current_val);
        app->current_value = (uint32_t)current_val;
    } else {
        app->current_value = 0;
    }
}

static bool load_nfc_file(AdvancedUidApp* app) {
    DialogsFileBrowserOptions browser_options;
    dialog_file_browser_set_basic_options(&browser_options, ".nfc", NULL);
    browser_options.hide_ext = false;
    
    FuriString* file_path = furi_string_alloc();
    furi_string_set(file_path, STORAGE_APP_DATA_PATH_PREFIX);
    
    bool file_selected = dialog_file_browser_show(app->dialogs, file_path, file_path, &browser_options);
    
    if(!file_selected) {
        furi_string_free(file_path);
        return false;
    }
    
    Storage* storage = furi_record_open(RECORD_STORAGE);
    Stream* stream = file_stream_alloc(storage);
    
    bool file_loaded = false;
    
    if(file_stream_open(stream, furi_string_get_cstr(file_path), FSAM_READ, FSOM_OPEN_EXISTING)) {
        FuriString* line = furi_string_alloc();
        char uid_found[17] = {0};
        bool uid_extracted = false;
        uint8_t detected_uid_len = 0;
        
        // Lire le fichier ligne par ligne pour trouver l'UID
        while(stream_read_line(stream, line)) {
            const char* line_str = furi_string_get_cstr(line);
            
            // Chercher la ligne UID
            if(strstr(line_str, "UID:") == line_str) {
                // Extraire l'UID après "UID: "
                const char* uid_start = line_str + 5; // Skip "UID: "
                
                // Nettoyer l'UID (enlever espaces et caractères non-hex)
                uint8_t uid_pos = 0;
                for(const char* c = uid_start; *c != '\0' && uid_pos < 16; c++) {
                    if((*c >= '0' && *c <= '9') || (*c >= 'A' && *c <= 'F') || (*c >= 'a' && *c <= 'f')) {
                        uid_found[uid_pos++] = (*c >= 'a') ? (*c - 'a' + 'A') : *c;
                    }
                }
                uid_found[uid_pos] = '\0';
                detected_uid_len = uid_pos / 2;
                
                if(detected_uid_len >= 4 && detected_uid_len <= 8) {
                    uid_extracted = true;
                    break;
                }
            }
        }
        
        if(uid_extracted) {
            // Déterminer la technologie basée sur l'UID et le contenu du fichier
            // Fermer et rouvrir le stream pour revenir au début
            file_stream_close(stream);
            if(file_stream_open(stream, furi_string_get_cstr(file_path), FSAM_READ, FSOM_OPEN_EXISTING)) {
                furi_string_reset(line);
                
                NfcTechnology detected_tech = TechMifareClassic; // Par défaut
                
                // Analyser le contenu pour détecter le type
                while(stream_read_line(stream, line)) {
                    const char* line_str = furi_string_get_cstr(line);
                    
                    if(strstr(line_str, "Device type:")) {
                        if(strstr(line_str, "MIFARE Classic")) {
                            detected_tech = TechMifareClassic;
                        } else if(strstr(line_str, "MIFARE Ultralight")) {
                            detected_tech = TechMifareUltralight;
                        } else if(strstr(line_str, "NTAG213")) {
                            detected_tech = TechNTAG213;
                        } else if(strstr(line_str, "NTAG215")) {
                            detected_tech = TechNTAG215;
                        } else if(strstr(line_str, "NTAG216")) {
                            detected_tech = TechNTAG216;
                        }
                        break;
                    }
                }
                
                // Si la détection automatique a échoué, utiliser la longueur de l'UID
                if(detected_tech == TechMifareClassic && detected_uid_len == 7) {
                    detected_tech = TechMifareUltralight;
                }
                
                // Configurer l'application avec les données extraites
                app->tech = detected_tech;
                app->uid_len = detected_uid_len;
                strcpy(app->uid, uid_found);
                strcpy(app->edit_uid, uid_found);
                
                // Extraire le nom du fichier pour l'affichage
                const char* filename_start = strrchr(furi_string_get_cstr(file_path), '/');
                if(filename_start) {
                    filename_start++;
                } else {
                    filename_start = furi_string_get_cstr(file_path);
                }
                strncpy(app->loaded_filename, filename_start, sizeof(app->loaded_filename) - 1);
                app->loaded_filename[sizeof(app->loaded_filename) - 1] = '\0';
                
                // Configurer les paramètres par défaut selon le type détecté
                switch(detected_tech) {
                    case TechMifareClassic:
                        app->increment_offset = (detected_uid_len > 4) ? (detected_uid_len * 2 - 4) : 4;
                        app->increment_length = 4;
                        break;
                    default:
                        app->increment_offset = (detected_uid_len > 2) ? (detected_uid_len * 2 - 4) : 4;
                        app->increment_length = 4;
                        break;
                }
                
                app->increment_step = 1;
                app->auto_delay_ms = 1000;
                app->fuzzer_delay_ms = 500;
                app->fuzzer_index = 0;
                app->fuzzer_random_mode = false;
                app->max_value = (1 << (app->increment_length * 4)) - 1;
                app->uid_changed = false;
                app->file_loaded = true;
                
                // Calculer la valeur actuelle
                if(app->increment_offset + app->increment_length <= strlen(app->uid)) {
                    unsigned int current_val = 0;
                    char temp_str[9] = {0};
                    strncpy(temp_str, &app->uid[app->increment_offset], app->increment_length);
                    sscanf(temp_str, "%X", &current_val);
                    app->current_value = (uint32_t)current_val;
                } else {
                    app->current_value = 0;
                }
                
                file_loaded = true;
            }
        }
        
        furi_string_free(line);
        file_stream_close(stream);
    }
    
    stream_free(stream);
    furi_record_close(RECORD_STORAGE);
    furi_string_free(file_path);
    
    return file_loaded;
}

static void generate_random_uid(AdvancedUidApp* app) {
    for(uint8_t i = 0; i < app->uid_len * 2; i++) {
        uint8_t random_val = furi_hal_random_get() % 16;
        if(random_val < 10) {
            app->uid[i] = '0' + random_val;
        } else {
            app->uid[i] = 'A' + (random_val - 10);
        }
    }
    app->uid[app->uid_len * 2] = '\0';
    
    switch(app->tech) {
        case TechMifareUltralight:
        case TechNTAG213:
        case TechNTAG215:
        case TechNTAG216:
            app->uid[0] = '0';
            app->uid[1] = '4';
            break;
        case TechIso15693:
            app->uid[0] = 'E';
            app->uid[1] = '0';
            break;
        default:
            break;
    }
    
    app->uid_changed = true;
}

static void fuzzer_next_uid(AdvancedUidApp* app) {
    if(!app->fuzzer_random_mode) {
        const char** uid_list = NULL;
        uint8_t list_count = 0;
        
        switch(app->uid_len) {
            case 4:
                uid_list = common_uids_4bytes;
                list_count = COMMON_UIDS_4BYTES_COUNT;
                break;
            case 7:
                uid_list = common_uids_7bytes;
                list_count = COMMON_UIDS_7BYTES_COUNT;
                break;
            case 8:
                uid_list = common_uids_8bytes;
                list_count = COMMON_UIDS_8BYTES_COUNT;
                break;
            default:
                generate_random_uid(app);
                return;
        }
        
        if(uid_list && list_count > 0) {
            strcpy(app->uid, uid_list[app->fuzzer_index]);
            app->fuzzer_index = (app->fuzzer_index + 1) % list_count;
            
            if(app->fuzzer_index == 0) {
                app->fuzzer_random_mode = true;
            }
        }
    } else {
        generate_random_uid(app);
        return;
    }
    
    app->uid_changed = true;
}

static void increment_uid(AdvancedUidApp* app) {
    if(app->increment_offset + app->increment_length <= strlen(app->uid)) {
        app->current_value = (app->current_value + app->increment_step) & app->max_value;
        
        char format_str[8];
        snprintf(format_str, sizeof(format_str), "%%0%dX", app->increment_length);
        snprintf(&app->uid[app->increment_offset], app->increment_length + 1, format_str, app->current_value);
        
        app->uid_changed = true;
    }
}

static void update_nfc_data(AdvancedUidApp* app) {
    uint8_t uid_bytes[10] = {0};
    hex_string_to_bytes(app->uid, uid_bytes, app->uid_len);
    
    switch(app->tech) {
        case TechMifareClassic:
            if(app->mf_classic_data) {
                memcpy(app->mf_classic_data->iso14443_3a_data->uid, uid_bytes, app->uid_len);
                app->mf_classic_data->iso14443_3a_data->uid_len = app->uid_len;
            }
            break;
        case TechMifareUltralight:
        case TechNTAG213:
        case TechNTAG215:
        case TechNTAG216:
            if(app->mf_ultralight_data) {
                memcpy(app->mf_ultralight_data->iso14443_3a_data->uid, uid_bytes, app->uid_len);
                app->mf_ultralight_data->iso14443_3a_data->uid_len = app->uid_len;
            }
            break;
        case TechFelica:
        case TechIso15693:
        case TechNum:
        default:
            if(app->iso14443_3a_data) {
                memcpy(app->iso14443_3a_data->uid, uid_bytes, app->uid_len);
                app->iso14443_3a_data->uid_len = app->uid_len;
            }
            break;
    }
}

static void restart_emulation_if_needed(AdvancedUidApp* app) {
    if(app->uid_changed && app->is_emulating) {
        if(app->nfc_listener) {
            nfc_listener_stop(app->nfc_listener);
            nfc_listener_free(app->nfc_listener);
            app->nfc_listener = NULL;
        }
        
        update_nfc_data(app);
        
        NfcProtocol protocol;
        void* protocol_data = NULL;
        
        switch(app->tech) {
            case TechMifareClassic:
                protocol = NfcProtocolMfClassic;
                protocol_data = app->mf_classic_data;
                break;
            case TechMifareUltralight:
            case TechNTAG213:
            case TechNTAG215:
            case TechNTAG216:
                protocol = NfcProtocolMfUltralight;
                protocol_data = app->mf_ultralight_data;
                break;
            default:
                protocol = NfcProtocolIso14443_3a;
                protocol_data = app->iso14443_3a_data;
                break;
        }
        
        app->nfc_listener = nfc_listener_alloc(app->nfc, protocol, protocol_data);
        if(app->nfc_listener) {
            nfc_listener_start(app->nfc_listener, NULL, NULL);
        }
        
        app->uid_changed = false;
    }
}

static void auto_timer_callback(void* context) {
    AdvancedUidApp* app = context;
    if(app->auto_mode && app->is_emulating) {
        increment_uid(app);
        restart_emulation_if_needed(app);
        notification_message(app->notifications, &sequence_single_vibro);
    }
}

static void fuzzer_timer_callback(void* context) {
    AdvancedUidApp* app = context;
    if(app->fuzzer_mode && app->is_emulating) {
        fuzzer_next_uid(app);
        restart_emulation_if_needed(app);
        notification_message(app->notifications, &sequence_single_vibro);
    }
}

static int32_t nfc_emulation_thread(void* context) {
    AdvancedUidApp* app = context;
    
    uint8_t uid_bytes[10] = {0};
    hex_string_to_bytes(app->uid, uid_bytes, app->uid_len);
    
    NfcProtocol protocol;
    void* protocol_data = NULL;
    
    switch(app->tech) {
        case TechMifareClassic:
            protocol = NfcProtocolMfClassic;
            if(!app->mf_classic_data) {
                app->mf_classic_data = mf_classic_alloc();
            }
            
            memcpy(app->mf_classic_data->iso14443_3a_data->uid, uid_bytes, app->uid_len);
            app->mf_classic_data->iso14443_3a_data->uid_len = app->uid_len;
            app->mf_classic_data->iso14443_3a_data->atqa[0] = tech_atqa[app->tech] & 0xFF;
            app->mf_classic_data->iso14443_3a_data->atqa[1] = (tech_atqa[app->tech] >> 8) & 0xFF;
            app->mf_classic_data->iso14443_3a_data->sak = tech_sak[app->tech];
            app->mf_classic_data->type = MfClassicType1k;
            protocol_data = app->mf_classic_data;
            break;
            
        case TechMifareUltralight:
        case TechNTAG213:
        case TechNTAG215:
        case TechNTAG216:
            protocol = NfcProtocolMfUltralight;
            if(!app->mf_ultralight_data) {
                app->mf_ultralight_data = mf_ultralight_alloc();
            }
            
            memcpy(app->mf_ultralight_data->iso14443_3a_data->uid, uid_bytes, app->uid_len);
            app->mf_ultralight_data->iso14443_3a_data->uid_len = app->uid_len;
            app->mf_ultralight_data->iso14443_3a_data->atqa[0] = tech_atqa[app->tech] & 0xFF;
            app->mf_ultralight_data->iso14443_3a_data->atqa[1] = (tech_atqa[app->tech] >> 8) & 0xFF;
            app->mf_ultralight_data->iso14443_3a_data->sak = tech_sak[app->tech];
            
            switch(app->tech) {
                case TechMifareUltralight:
                    app->mf_ultralight_data->type = MfUltralightTypeUL11;
                    break;
                case TechNTAG213:
                    app->mf_ultralight_data->type = MfUltralightTypeNTAG213;
                    break;
                case TechNTAG215:
                    app->mf_ultralight_data->type = MfUltralightTypeNTAG215;
                    break;
                case TechNTAG216:
                    app->mf_ultralight_data->type = MfUltralightTypeNTAG216;
                    break;
                default:
                    app->mf_ultralight_data->type = MfUltralightTypeUL11;
                    break;
            }
            
            protocol_data = app->mf_ultralight_data;
            break;
            
        default:
            protocol = NfcProtocolIso14443_3a;
            if(!app->iso14443_3a_data) {
                app->iso14443_3a_data = iso14443_3a_alloc();
            }
            
            memcpy(app->iso14443_3a_data->uid, uid_bytes, app->uid_len);
            app->iso14443_3a_data->uid_len = app->uid_len;
            app->iso14443_3a_data->atqa[0] = tech_atqa[app->tech] & 0xFF;
            app->iso14443_3a_data->atqa[1] = (tech_atqa[app->tech] >> 8) & 0xFF;
            app->iso14443_3a_data->sak = tech_sak[app->tech];
            
            protocol_data = app->iso14443_3a_data;
            break;
    }
    
    app->nfc_listener = nfc_listener_alloc(app->nfc, protocol, protocol_data);
    
    if(!app->nfc_listener) {
        return -1;
    }
    
    nfc_listener_start(app->nfc_listener, NULL, NULL);
    
    if(app->auto_mode) {
        furi_timer_start(app->auto_timer, app->auto_delay_ms);
    } else if(app->fuzzer_mode) {
        furi_timer_start(app->fuzzer_timer, app->fuzzer_delay_ms);
    }
    
    while(app->is_emulating) {
        furi_delay_ms(50);
    }
    
    if(app->auto_mode) {
        furi_timer_stop(app->auto_timer);
    }
    if(app->fuzzer_mode) {
        furi_timer_stop(app->fuzzer_timer);
    }
    
    nfc_listener_stop(app->nfc_listener);
    nfc_listener_free(app->nfc_listener);
    app->nfc_listener = NULL;
    
    return 0;
}

static void start_emulation(AdvancedUidApp* app) {
    if(!app->is_emulating) {
        app->is_emulating = true;
        app->uid_changed = false;
        app->emulation_thread = furi_thread_alloc();
        furi_thread_set_name(app->emulation_thread, "NfcEmuThread");
        furi_thread_set_stack_size(app->emulation_thread, 4096);
        furi_thread_set_context(app->emulation_thread, app);
        furi_thread_set_callback(app->emulation_thread, nfc_emulation_thread);
        furi_thread_start(app->emulation_thread);
        
        notification_message(app->notifications, &sequence_success);
    }
}

static void stop_emulation(AdvancedUidApp* app) {
    if(app->is_emulating) {
        app->is_emulating = false;
        if(app->emulation_thread) {
            furi_thread_join(app->emulation_thread);
            furi_thread_free(app->emulation_thread);
            app->emulation_thread = NULL;
        }
        
        notification_message(app->notifications, &sequence_error);
    }
}

static void draw_callback(Canvas* canvas, void* ctx) {
    AdvancedUidApp* app = ctx;
    char temp_str[64];
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 0, 10, "Advanced UID Tool");
    canvas_set_font(canvas, FontSecondary);

    switch(app->state) {
        case StateMenu:
            canvas_draw_str(canvas, 0, 22, "Select option:");
            
            // Calcul du défilement pour le menu principal
            const uint8_t menu_items_per_screen = 4; // Nombre d'items visibles à la fois
            uint8_t menu_start = app->menu_scroll_offset;
            uint8_t menu_end = menu_start + menu_items_per_screen;
            if(menu_end > MenuNum) menu_end = MenuNum;
            
            // Affichage des items du menu avec défilement
            for(int i = menu_start; i < menu_end; i++) {
                uint8_t display_pos = i - menu_start;
                if(i == app->menu_index) {
                    canvas_draw_str(canvas, 5, 34 + display_pos * 8, ">");
                }
                canvas_draw_str(canvas, 15, 34 + display_pos * 8, menu_names[i]);
            }
            
            // Indicateurs de défilement
            if(app->menu_scroll_offset > 0) {
                canvas_draw_str(canvas, 120, 30, "^"); // Flèche vers le haut
            }
            if(menu_end < MenuNum) {
                canvas_draw_str(canvas, 120, 58, "v"); // Flèche vers le bas
            }
            
            canvas_draw_str(canvas, 0, 64, "OK: Select  Back: Exit");
            break;
            
        case StateLoadFile:
            canvas_draw_str(canvas, 0, 22, "Loading NFC file...");
            canvas_draw_str(canvas, 0, 32, "Please wait...");
            break;
            
        case StateEditUID:
            if(app->file_loaded) {
                // Tronquer le nom de fichier si trop long pour éviter la troncature
                char short_filename[32];
                if(strlen(app->loaded_filename) > 30) {
                    strncpy(short_filename, app->loaded_filename, 27);
                    short_filename[27] = '\0';
                    strcat(short_filename, "...");
                } else {
                    strcpy(short_filename, app->loaded_filename);
                }
                snprintf(temp_str, sizeof(temp_str), "Edit UID (From: %s)", short_filename);
                canvas_draw_str(canvas, 0, 22, temp_str);
            } else {
                snprintf(temp_str, sizeof(temp_str), "Edit UID (%s)", tech_names[app->tech]);
                canvas_draw_str(canvas, 0, 22, temp_str);
            }
            
            snprintf(temp_str, sizeof(temp_str), "Length: %d bytes", app->uid_len);
            canvas_draw_str(canvas, 0, 32, temp_str);
            
            canvas_draw_str(canvas, 0, 42, "UID:");
            canvas_draw_str(canvas, 30, 42, app->edit_uid);
            
            if(app->edit_position < strlen(app->edit_uid)) {
                canvas_draw_str(canvas, 30 + app->edit_position * 6, 50, "^");
            }
            
            canvas_draw_str(canvas, 0, 60, "Up/Dn: Edit  OK: Next");
            break;
            
        case StateSettings:
            canvas_draw_str(canvas, 0, 22, "Settings:");
            
            // Calcul du défilement pour les settings
            const uint8_t settings_items_per_screen = 4; // Nombre d'items visibles à la fois
            uint8_t settings_start = app->settings_scroll_offset;
            uint8_t settings_end = settings_start + settings_items_per_screen;
            if(settings_end > SettingsCount) settings_end = SettingsCount;
            
            // Affichage des settings avec défilement
            for(int i = settings_start; i < settings_end; i++) {
                uint8_t display_pos = i - settings_start;
                if(i == app->settings_index) {
                    canvas_draw_str(canvas, 5, 34 + display_pos * 8, ">");
                }
                
                switch(i) {
                    case SettingsStep:
                        snprintf(temp_str, sizeof(temp_str), "%s: %lu", settings_names[i], app->increment_step);
                        break;
                    case SettingsOffset:
                        snprintf(temp_str, sizeof(temp_str), "%s: %d", settings_names[i], app->increment_offset);
                        break;
                    case SettingsLength:
                        snprintf(temp_str, sizeof(temp_str), "%s: %d", settings_names[i], app->increment_length);
                        break;
                    case SettingsAutoDelay:
                        snprintf(temp_str, sizeof(temp_str), "%s: %lu", settings_names[i], app->auto_delay_ms);
                        break;
                    case SettingsFuzzerDelay:
                        snprintf(temp_str, sizeof(temp_str), "%s: %lu", settings_names[i], app->fuzzer_delay_ms);
                        break;
                }
                canvas_draw_str(canvas, 15, 34 + display_pos * 8, temp_str);
            }
            
            // Indicateurs de défilement pour settings
            if(app->settings_scroll_offset > 0) {
                canvas_draw_str(canvas, 120, 30, "^"); // Flèche vers le haut
            }
            if(settings_end < SettingsCount) {
                canvas_draw_str(canvas, 120, 58, "v"); // Flèche vers le bas
            }
            
            canvas_draw_str(canvas, 0, 64, "Left/Right: Change  OK: Run");
            break;
            
        case StateRunning:
            if(app->file_loaded) {
                // Tronquer le nom de fichier si trop long
                char short_filename[48];
                if(strlen(app->loaded_filename) > 45) {
                    strncpy(short_filename, app->loaded_filename, 42);
                    short_filename[42] = '\0';
                    strcat(short_filename, "...");
                } else {
                    strcpy(short_filename, app->loaded_filename);
                }
                snprintf(temp_str, sizeof(temp_str), "File: %s", short_filename);
                canvas_draw_str(canvas, 0, 22, temp_str);
            } else {
                snprintf(temp_str, sizeof(temp_str), "Tech: %s", tech_names[app->tech]);
                canvas_draw_str(canvas, 0, 22, temp_str);
            }
            
            snprintf(temp_str, sizeof(temp_str), "UID: %s", app->uid);
            canvas_draw_str(canvas, 0, 32, temp_str);
            
            snprintf(temp_str, sizeof(temp_str), "Count: %lu (Step:%lu)", app->current_value, app->increment_step);
            canvas_draw_str(canvas, 0, 42, temp_str);
            
            if(app->is_emulating) {
                canvas_draw_str(canvas, 0, 52, "EMULATING (Manual)");
                canvas_draw_str(canvas, 0, 62, "OK: Stop  Left: Auto  Right: Fuzz");
            } else {
                canvas_draw_str(canvas, 0, 52, "Ready (Manual Mode)");
                canvas_draw_str(canvas, 0, 62, "OK: Start  Left: Auto  Right: Fuzz");
            }
            break;
            
        case StateAuto:
            if(app->file_loaded) {
                // Tronquer le nom de fichier si trop long
                char short_filename[48];
                if(strlen(app->loaded_filename) > 45) {
                    strncpy(short_filename, app->loaded_filename, 42);
                    short_filename[42] = '\0';
                    strcat(short_filename, "...");
                } else {
                    strcpy(short_filename, app->loaded_filename);
                }
                snprintf(temp_str, sizeof(temp_str), "File: %s", short_filename);
                canvas_draw_str(canvas, 0, 22, temp_str);
            } else {
                snprintf(temp_str, sizeof(temp_str), "Tech: %s", tech_names[app->tech]);
                canvas_draw_str(canvas, 0, 22, temp_str);
            }
            
            snprintf(temp_str, sizeof(temp_str), "UID: %s", app->uid);
            canvas_draw_str(canvas, 0, 32, temp_str);
            
            snprintf(temp_str, sizeof(temp_str), "Count: %lu (%lums)", app->current_value, app->auto_delay_ms);
            canvas_draw_str(canvas, 0, 42, temp_str);
            
            if(app->is_emulating) {
                canvas_draw_str(canvas, 0, 52, "AUTO EMULATING...");
                canvas_draw_str(canvas, 0, 62, "OK: Stop  Left: Man  Right: Fuzz");
            } else {
                canvas_draw_str(canvas, 0, 52, "Ready (Auto Mode)");
                canvas_draw_str(canvas, 0, 62, "OK: Start  Left: Man  Right: Fuzz");
            }
            break;
            
        case StateFuzzer:
            if(app->file_loaded) {
                // Tronquer le nom de fichier si trop long
                char short_filename[48];
                if(strlen(app->loaded_filename) > 45) {
                    strncpy(short_filename, app->loaded_filename, 42);
                    short_filename[42] = '\0';
                    strcat(short_filename, "...");
                } else {
                    strcpy(short_filename, app->loaded_filename);
                }
                snprintf(temp_str, sizeof(temp_str), "File: %s", short_filename);
                canvas_draw_str(canvas, 0, 22, temp_str);
            } else {
                snprintf(temp_str, sizeof(temp_str), "Tech: %s", tech_names[app->tech]);
                canvas_draw_str(canvas, 0, 22, temp_str);
            }
            
            snprintf(temp_str, sizeof(temp_str), "UID: %s", app->uid);
            canvas_draw_str(canvas, 0, 32, temp_str);
            
            snprintf(temp_str, sizeof(temp_str), "Mode: %s (%lums)", 
                    app->fuzzer_random_mode ? "Random" : "Predefined", app->fuzzer_delay_ms);
            canvas_draw_str(canvas, 0, 42, temp_str);
            
            if(app->is_emulating) {
                canvas_draw_str(canvas, 0, 52, "FUZZER EMULATING...");
                canvas_draw_str(canvas, 0, 62, "OK: Stop  Left: Auto  Right: Man");
            } else {
                canvas_draw_str(canvas, 0, 52, "Ready (Fuzzer Mode)");
                canvas_draw_str(canvas, 0, 62, "OK: Start  Left: Auto  Right: Man");
            }
            break;
    }
}

static void input_callback(InputEvent* input_event, void* ctx) {
    AdvancedUidApp* app = ctx;
    furi_message_queue_put(app->event_queue, input_event, FuriWaitForever);
}

static AdvancedUidApp* advanced_uid_app_alloc() {
    AdvancedUidApp* app = malloc(sizeof(AdvancedUidApp));
    
    app->tech = TechMifareClassic;
    app->state = StateMenu;
    app->is_emulating = false;
    app->auto_mode = false;
    app->fuzzer_mode = false;
    app->uid_changed = false;
    app->file_loaded = false;
    app->emulation_thread = NULL;
    app->nfc_listener = NULL;
    app->iso14443_3a_data = NULL;
    app->mf_ultralight_data = NULL;
    app->mf_classic_data = NULL;
    app->menu_index = 0;
    app->menu_scroll_offset = 0;
    app->edit_position = 0;
    app->settings_index = 0;
    app->settings_scroll_offset = 0;
    strcpy(app->loaded_filename, "");
    
    app->nfc = nfc_alloc();
    app->dialogs = furi_record_open(RECORD_DIALOGS);
    
    init_uid_for_tech(app);
    
    app->gui = furi_record_open(RECORD_GUI);
    app->view_port = view_port_alloc();
    view_port_draw_callback_set(app->view_port, draw_callback, app);
    view_port_input_callback_set(app->view_port, input_callback, app);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
    
    app->event_queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    
    app->auto_timer = furi_timer_alloc(auto_timer_callback, FuriTimerTypePeriodic, app);
    app->fuzzer_timer = furi_timer_alloc(fuzzer_timer_callback, FuriTimerTypePeriodic, app);
    
    return app;
}

static void advanced_uid_app_free(AdvancedUidApp* app) {
    stop_emulation(app);
    
    furi_timer_free(app->auto_timer);
    furi_timer_free(app->fuzzer_timer);
    
    if(app->iso14443_3a_data) {
        iso14443_3a_free(app->iso14443_3a_data);
    }
    
    if(app->mf_ultralight_data) {
        mf_ultralight_free(app->mf_ultralight_data);
    }
    
    if(app->mf_classic_data) {
        mf_classic_free(app->mf_classic_data);
    }
    
    if(app->nfc) {
        nfc_free(app->nfc);
    }
    
    view_port_enabled_set(app->view_port, false);
    gui_remove_view_port(app->gui, app->view_port);
    view_port_free(app->view_port);
    
    furi_message_queue_free(app->event_queue);
    
    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_DIALOGS);
    free(app);
}

int32_t advanced_uid_app(void* p) {
    UNUSED(p);
    AdvancedUidApp* app = advanced_uid_app_alloc();
    
    InputEvent event;
    bool running = true;
    
    while(running) {
        if(furi_message_queue_get(app->event_queue, &event, 50) == FuriStatusOk) {
            if(event.type == InputTypePress) {
                switch(app->state) {
                    case StateMenu:
                        switch(event.key) {
                            case InputKeyUp:
                                app->menu_index = (app->menu_index - 1 + MenuNum) % MenuNum;
                                
                                // Ajuster le défilement si nécessaire
                                if(app->menu_index < app->menu_scroll_offset) {
                                    app->menu_scroll_offset = app->menu_index;
                                }
                                break;
                            case InputKeyDown:
                                app->menu_index = (app->menu_index + 1) % MenuNum;
                                
                                // Ajuster le défilement si nécessaire (4 items par écran)
                                if(app->menu_index >= app->menu_scroll_offset + 4) {
                                    app->menu_scroll_offset = app->menu_index - 3;
                                }
                                break;
                            case InputKeyOk:
                                if(app->menu_index == MenuLoadFile) {
                                    app->state = StateLoadFile;
                                    view_port_update(app->view_port);
                                    
                                    if(load_nfc_file(app)) {
                                        notification_message(app->notifications, &sequence_success);
                                        app->state = StateEditUID;
                                        app->edit_position = 0;
                                    } else {
                                        notification_message(app->notifications, &sequence_error);
                                        app->state = StateMenu;
                                    }
                                } else {
                                    app->tech = app->menu_index;
                                    init_uid_for_tech(app);
                                    app->state = StateEditUID;
                                    app->edit_position = 0;
                                }
                                break;
                            case InputKeyBack:
                                running = false;
                                break;
                            default:
                                break;
                        }
                        break;
                        
                    case StateLoadFile:
                        // État transitoire, ne pas traiter d'événements
                        break;
                        
                    case StateEditUID:
                        switch(event.key) {
                            case InputKeyUp:
                                if(app->edit_position < strlen(app->edit_uid)) {
                                    char c = app->edit_uid[app->edit_position];
                                    if(c >= '0' && c <= '9') {
                                        app->edit_uid[app->edit_position] = (c == '9') ? 'A' : c + 1;
                                    } else if(c >= 'A' && c <= 'F') {
                                        app->edit_uid[app->edit_position] = (c == 'F') ? '0' : c + 1;
                                    }
                                }
                                break;
                            case InputKeyDown:
                                if(app->edit_position < strlen(app->edit_uid)) {
                                    char c = app->edit_uid[app->edit_position];
                                    if(c >= '0' && c <= '9') {
                                        app->edit_uid[app->edit_position] = (c == '0') ? 'F' : c - 1;
                                    } else if(c >= 'A' && c <= 'F') {
                                        app->edit_uid[app->edit_position] = (c == 'A') ? '9' : c - 1;
                                    }
                                }
                                break;
                            case InputKeyLeft:
                                if(app->edit_position > 0) {
                                    app->edit_position--;
                                }
                                break;
                            case InputKeyRight:
                                if(app->edit_position < strlen(app->edit_uid) - 1) {
                                    app->edit_position++;
                                }
                                break;
                            case InputKeyOk:
                                strcpy(app->uid, app->edit_uid);
                                // Recalculer current_value après édition manuelle
                                if(app->increment_offset + app->increment_length <= strlen(app->uid)) {
                                    unsigned int current_val = 0;
                                    char temp_str[9] = {0};
                                    strncpy(temp_str, &app->uid[app->increment_offset], app->increment_length);
                                    sscanf(temp_str, "%X", &current_val);
                                    app->current_value = (uint32_t)current_val;
                                }
                                app->state = StateSettings;
                                break;
                            case InputKeyBack:
                                app->state = StateMenu;
                                break;
                            default:
                                break;
                        }
                        break;
                        
                    case StateSettings:
                        switch(event.key) {
                            case InputKeyUp:
                                app->settings_index = (app->settings_index - 1 + SettingsCount) % SettingsCount;
                                
                                // Ajuster le défilement si nécessaire
                                if(app->settings_index < app->settings_scroll_offset) {
                                    app->settings_scroll_offset = app->settings_index;
                                }
                                break;
                            case InputKeyDown:
                                app->settings_index = (app->settings_index + 1) % SettingsCount;
                                
                                // Ajuster le défilement si nécessaire (4 items par écran)
                                if(app->settings_index >= app->settings_scroll_offset + 4) {
                                    app->settings_scroll_offset = app->settings_index - 3;
                                }
                                break;
                            case InputKeyLeft:
                                switch(app->settings_index) {
                                    case SettingsStep:
                                        if(app->increment_step > 1) app->increment_step--;
                                        break;
                                    case SettingsOffset:
                                        if(app->increment_offset > 0) app->increment_offset--;
                                        break;
                                    case SettingsLength:
                                        if(app->increment_length > 2) app->increment_length -= 2;
                                        break;
                                    case SettingsAutoDelay:
                                        if(app->auto_delay_ms > 100) app->auto_delay_ms -= 100;
                                        break;
                                    case SettingsFuzzerDelay:
                                        if(app->fuzzer_delay_ms > 100) app->fuzzer_delay_ms -= 100;
                                        break;
                                }
                                app->max_value = (1 << (app->increment_length * 4)) - 1;
                                break;
                            case InputKeyRight:
                                switch(app->settings_index) {
                                    case SettingsStep:
                                        if(app->increment_step < 256) app->increment_step++;
                                        break;
                                    case SettingsOffset:
                                        if(app->increment_offset < (app->uid_len * 2) - app->increment_length) 
                                            app->increment_offset++;
                                        break;
                                    case SettingsLength:
                                        if(app->increment_length < 8 && 
                                           app->increment_offset + app->increment_length + 2 <= app->uid_len * 2) 
                                            app->increment_length += 2;
                                        break;
                                    case SettingsAutoDelay:
                                        if(app->auto_delay_ms < 10000) app->auto_delay_ms += 100;
                                        break;
                                    case SettingsFuzzerDelay:
                                        if(app->fuzzer_delay_ms < 10000) app->fuzzer_delay_ms += 100;
                                        break;
                                }
                                app->max_value = (1 << (app->increment_length * 4)) - 1;
                                break;
                            case InputKeyOk:
                                app->state = StateRunning;
                                app->auto_mode = false;
                                app->fuzzer_mode = false;
                                break;
                            case InputKeyBack:
                                app->state = StateEditUID;
                                break;
                            default:
                                break;
                        }
                        break;
                        
                    case StateRunning:
                        switch(event.key) {
                            case InputKeyOk:
                                if(app->is_emulating) {
                                    stop_emulation(app);
                                } else {
                                    app->auto_mode = false;
                                    app->fuzzer_mode = false;
                                    start_emulation(app);
                                }
                                break;
                            case InputKeyLeft:
                                if(!app->is_emulating) {
                                    app->state = StateAuto;
                                }
                                break;
                            case InputKeyRight:
                                if(!app->is_emulating) {
                                    app->state = StateFuzzer;
                                }
                                break;
                            case InputKeyUp:
                                increment_uid(app);
                                if(app->is_emulating) {
                                    restart_emulation_if_needed(app);
                                }
                                notification_message(app->notifications, &sequence_single_vibro);
                                break;
                            case InputKeyBack:
                                stop_emulation(app);
                                app->state = StateSettings;
                                break;
                            default:
                                break;
                        }
                        break;
                        
                    case StateAuto:
                        switch(event.key) {
                            case InputKeyOk:
                                if(app->is_emulating) {
                                    stop_emulation(app);
                                } else {
                                    app->auto_mode = true;
                                    app->fuzzer_mode = false;
                                    start_emulation(app);
                                }
                                break;
                            case InputKeyLeft:
                                if(!app->is_emulating) {
                                    app->state = StateRunning;
                                }
                                break;
                            case InputKeyRight:
                                if(!app->is_emulating) {
                                    app->state = StateFuzzer;
                                }
                                break;
                            case InputKeyBack:
                                stop_emulation(app);
                                app->state = StateSettings;
                                break;
                            default:
                                break;
                        }
                        break;
                        
                    case StateFuzzer:
                        switch(event.key) {
                            case InputKeyOk:
                                if(app->is_emulating) {
                                    stop_emulation(app);
                                } else {
                                    app->auto_mode = false;
                                    app->fuzzer_mode = true;
                                    app->fuzzer_index = 0;
                                    app->fuzzer_random_mode = false;
                                    start_emulation(app);
                                }
                                break;
                            case InputKeyLeft:
                                if(!app->is_emulating) {
                                    app->state = StateAuto;
                                }
                                break;
                            case InputKeyRight:
                                if(!app->is_emulating) {
                                    app->state = StateRunning;
                                }
                                break;
                            case InputKeyUp:
                                fuzzer_next_uid(app);
                                if(app->is_emulating) {
                                    restart_emulation_if_needed(app);
                                }
                                notification_message(app->notifications, &sequence_single_vibro);
                                break;
                            case InputKeyDown:
                                app->fuzzer_random_mode = !app->fuzzer_random_mode;
                                if(!app->fuzzer_random_mode) {
                                    app->fuzzer_index = 0;
                                }
                                notification_message(app->notifications, &sequence_single_vibro);
                                break;
                            case InputKeyBack:
                                stop_emulation(app);
                                app->state = StateSettings;
                                break;
                            default:
                                break;
                        }
                        break;
                }
            }
        }
        view_port_update(app->view_port);
    }
    
    advanced_uid_app_free(app);
    return 0;
}