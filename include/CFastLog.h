#ifndef FAST_LOG_HEADER_GUARD
#define FAST_LOG_HEADER_GUARD

#pragma once

#include <cstring>
#include <cstdint>
#include <memory>
#include <string>
#include <experimental/string_view>
#include <iosfwd>
#include <type_traits>
#include <algorithm>


namespace fastlog
{
    /// Тип события в лог-файле
    enum class LogEventType
    {
        Undef = 0, Request, System, User, Timer
    };

    /// Уровень лога (приоритет)
    enum class LogLevel : uint8_t
    {
        UNDEF = 0, DBG, INFO, WARN, CRIT, NONE
    };

    constexpr unsigned long xsize = 32;

    using uid_t = std::array<char, xsize>;
    using str_t = std::basic_string<char>;

    /// Структура для записи токена в лог!
    ///
    /// !!! писать в лог токен нужно только так:
    /// LOG_INFO(fastlog::LogEventType::User) << fastlog::CTokenGUID{TokenString} << "Information for Output..." << strData;
    /// Если поставить CTokenGUID{TokenString} в потоке после строки с данными, то там нарушается извлечение токена!
    ///
    /// @todo Сейчас длина всегда 32 символа! (Нужна возможность использования строк произвольной длины...)
    ///
    struct CTokenGUID final
    {
        // CTOR -init-
        explicit CTokenGUID(const str_t str)
        {
            FromString(str);
        }

        void Read(uid_t& ref) const
        {
            std::memcpy(&ref.front(), &value.at(0), value.size());
        }

        void FromString(str_t guid)
        {
            if( guid.empty() )
            {
                // Запись <NULL> (все символы нулевые)
                std::fill(value.begin(), value.end(), 0);
            }
            else  // normal:
            {
                guid.resize(xsize, '+'); // TODO: Поддержка разных длин!
                std::copy(guid.cbegin(), guid.cend(), std::begin(value));
            }
        }

        str_t ToString(void) const noexcept
        {
            str_t str{"TOKEN"};

            str.assign(value.cbegin(), value.cend());

            return str;
        }

        bool IsEmpty(void) const noexcept
        {
            // Проверка на <NULL> (все символы нулевые)
            return  std::all_of( value.cbegin(), value.cend(),
                                 [](char x){  return 0 == x;  }
                               );
            // return (false);
        }

    private:
        // ARRAY for UID-string
        std::array<char, xsize> value = {};
    };

    /// Структура поддержки флага записи в БД
    struct SavingToDB final
    {
        // CTOR -init-
        explicit SavingToDB(bool yes) noexcept
          :  saving{ yes }
        { }

        const bool saving;
    };
    

    /// Уникальный! класс для записи информации в лог!
    class CFastLogLine final
    {
    public:
        CFastLogLine( LogEventType event, LogLevel level, char const * file, char const * function, uint32_t line);
        ~CFastLogLine() noexcept;

        CFastLogLine(CFastLogLine &&) = default;
        CFastLogLine& operator=(CFastLogLine &&) = default;

        bool stringify(std::ostream & os);

        CFastLogLine& operator<<(char arg);
        CFastLogLine& operator<<(int32_t arg);
        CFastLogLine& operator<<(uint32_t arg);
        CFastLogLine& operator<<(int64_t arg);
        CFastLogLine& operator<<(uint64_t arg);
        CFastLogLine& operator<<(double arg);
        CFastLogLine& operator<<(std::string const & arg);
        CFastLogLine& operator<<(std::experimental::string_view arg);
        CFastLogLine& operator<<(CTokenGUID const &);
        CFastLogLine& operator<<(SavingToDB const &);

        template < size_t N >
        CFastLogLine& operator<<(const char (&arg)[N])
        {
            encode(string_literal_t(arg));
            return *this;
        }

        template < typename Arg >
        typename std::enable_if < std::is_same < Arg, char const * >::value, CFastLogLine& >::type
        operator<<(Arg const & arg)
        {
            encode(arg);
            return *this;
        }

        template < typename Arg >
        typename std::enable_if < std::is_same < Arg, char * >::value, CFastLogLine& >::type
        operator<<(Arg const & arg)
        {
            encode(arg);
            return *this;
        }

        struct string_literal_t
        {
            explicit string_literal_t(char const * s) : m_s(s) {}
            char const * m_s;
        };

    private: // methods

        char* buffer();

        template < typename Arg >
        void encode(Arg arg);

        template < typename Arg >
        void encode(Arg arg, uint8_t type_id);

        void encode(char * arg);
        void encode(char const * arg);
        void encode(string_literal_t arg);
        void encode_c_string(char const * arg, const size_t length);

        bool resize_buffer_if_needed(const size_t additional_bytes);
        bool stringify(std::ostream & os, char * start, char const * const end);

    private:  //  data

        unsigned int  m_hasGuid = 0;
        unsigned int  m_forSave = 0;

        size_t m_bytes_used  = 0;
        size_t m_buffer_size = 0;

        std::unique_ptr< char[] > m_heap_buffer;

        char m_stack_buffer[256 - sizeof(m_hasGuid) - sizeof(m_forSave) - 2 * sizeof(size_t)
                                - sizeof(decltype(m_heap_buffer)) - 8 /* Reserved */];

    };
    
    /// Вспомогательный класс для логов
    /// (Используется через макрос!)
    struct CLogHelper final
    {
        /// CTOR -def-
        CLogHelper() = default;

        /// Операция 'вставки' строки в лог
        bool operator <= (CFastLogLine &);

    private:

        // const LogEventType m_Type;
        // str_t  m_Tag = "Test-Tag";
    };

    unsigned long LoggerPtrValue(void);

    void log_add_tag(const str_t  str);

    void set_log_level(LogLevel level);

    unsigned int get_log_level(void);
    
    bool is_logged(LogLevel level);

    bool is_opened(void);

    void close_log(void);

    /*
     * Негарантированное логирование. Используется кольцевой буфер для хранения строк.
     * При заполнении буфера наиболее старые строки в логе будут замещаться новыми.
     * Это позволяет избежать блокировки записи в случае, когда достигнут максимальный размер журнала
     * ring_buffer_size_mb - размер буфера в мегабайтах
     * Поскольку размер каждой строки в журнале равен 256  байт,
     * ring_buffer_size = ring_buffer_size_mb * 1024 * 1024 / 256
     */
    struct NonGuaranteedLogger
    {
        NonGuaranteedLogger(uint32_t buffer_size_mb)
          : ring_buffer_size_mb{ buffer_size_mb }
        { }

        uint32_t ring_buffer_size_mb;
    };

    /*
     * Гарантированное логирование, без потерь старых записей.
     */
    struct GuaranteedLogger
    {
        GuaranteedLogger(const str_t tags = "") noexcept
        {
            m_TagsInfo = tags;
        }

        str_t  m_TagsInfo;
    };

    /*
     * Функция initialize() должна быть вызвана до любого обращения к журналу.
     * log_directory - папка хранения файла журнала. Например - "/tmp/"
     * log_file_name - базовая часть имени файла журнала. Например - "fastlog"
     * При этом будут создаваться файлы в формате -
     * /tmp/fastlog.1.txt
     * /tmp/fastlog.2.txt
     * и т.д.
     * log_file_roll_size_mb - размер в мегабайтах, при котором происходит переход к новому файлу журнала.
     */
    void initialize(GuaranteedLogger     gl, std::string const & log_dir, std::string const & log_name, uint32_t size_mb, std::string const & log_path = "");
    /// @todo: вторая функция отличается одним параметром - лучше сделать один метод с полиморфным параметром...
    void initialize(NonGuaranteedLogger ngl, std::string const & log_dir, std::string const & log_name, uint32_t size_mb, std::string const & log_path = "");

}   // namespace fastlog


inline std::basic_ostream<char>& operator << (std::basic_ostream<char>& os, const fastlog::CTokenGUID& token) noexcept
{
    // TODO: check it!

    os << std::string{"(TOKEN:"} << token.ToString() << std::string{")"};

    return os;
}

inline std::basic_ostream<char>& operator << (std::basic_ostream<char>& os, const fastlog::SavingToDB&  save) noexcept
{
    // TODO: check it!

    os << std::string{"(SAVE:"} << std::string{ save.saving ? "True" : "False" } << std::string{")"};

    return os;
}

constexpr const char* file_name(const char* path) {
    const char* file = path;
    while (*path) {
        if (*path++ == '/') {
            file = path;
        }
    }
    return file;
}


const fastlog::LogEventType defEventType = fastlog::LogEventType::Undef;

/// ЛОГирование в файл: указать уровень сообщения (LogLevel) и его тип (LogEventType)
#define FAST_LOG(LEVEL, ETYPE)   fastlog::CLogHelper{} <= fastlog::CFastLogLine(ETYPE, LEVEL, file_name(__FILE__), __func__, __LINE__)

#define LOG_DBG(TYPE)  fastlog::is_logged(fastlog::LogLevel::DBG)  && FAST_LOG(fastlog::LogLevel::DBG,  TYPE)
#define LOG_INFO(TYPE) fastlog::is_logged(fastlog::LogLevel::INFO) && FAST_LOG(fastlog::LogLevel::INFO, TYPE)
#define LOG_WARN(TYPE) fastlog::is_logged(fastlog::LogLevel::WARN) && FAST_LOG(fastlog::LogLevel::WARN, TYPE)
#define LOG_CRIT(TYPE) fastlog::is_logged(fastlog::LogLevel::CRIT) && FAST_LOG(fastlog::LogLevel::CRIT, TYPE)


namespace fastlog
{

/// USE: Для логирования времени выполнения функции...
struct TimeExecute final
{
    // CTOR
    explicit TimeExecute(const str_t fName, const bool bIngore) noexcept
        : _name{ fName + "()" }, _ignore{bIngore}
    {
        if(!_ignore)
        {
            LOG_DBG(fastlog::LogEventType::Timer) << "FUNCTION " << _name << " <ENTER>";
        }
    }
    // DTOR
    ~TimeExecute(void) noexcept
    {
        if(!_ignore)
        {
            LOG_DBG(fastlog::LogEventType::Timer) << "FUNCTION " << _name << " <EXIT>";
        }
    }

private:
    // Не делать запись
    const bool _ignore;
    // Имя для записи
    const str_t  _name;
};


///  Параметр (из CFG): пишем время?
const bool NeedWriteTime() noexcept;


}  // ns 'fastlog'


//  Макрос для имени метода
#define  FUNC_NAME()  __func__
//  Вставлять в начале той функции, для которой мы хотим мерять время...
#define  LOG_FUNCTION_TIME()  fastlog::TimeExecute timeObjectFor{ FUNC_NAME(), !fastlog::NeedWriteTime() };


#endif /* FAST_LOG_HEADER_GUARD */
