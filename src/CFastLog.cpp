#include "CFastLog.h"

#include <cstring>
#include <chrono>
#include <ctime>
#include <thread>
#include <tuple>
#include <atomic>
#include <queue>
#include <fstream>
#include <sys/stat.h>
#include <iostream>

// #include <assert.h>

namespace
{

    /* Возвращает микросекунды после epoch */
    uint64_t timestamp_now()
    {
    	return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    }

    /* Формат метки времени [09-12-2019_00:09:59.598514] */
    void format_timestamp(std::ostream & os, uint64_t timestamp)
    {
        // Test the next 3 lines later!
        // auto duration = std::chrono::microseconds(timestamp);
        // std::chrono::high_resolution_clock::time_point time_point(duration);
        // std::time_t time_t = std::chrono::high_resolution_clock::to_time_t(time_point);
        std::time_t time_t = timestamp / 1000000;
        auto gmtime = std::gmtime(&time_t);
        char buffer[64] = { 0 };

        strftime(buffer, 64, "%d-%m-%Y_%T.", gmtime);
        char microseconds[7];
        sprintf(microseconds, "%06llu", timestamp % 1000000);
        os << "[TIME:" << buffer << microseconds << ']';
    }

    std::thread::id this_thread_id()
    {
        static thread_local const std::thread::id id = std::this_thread::get_id();
        return id;
    }

    template < typename T, typename Tuple >
    struct TupleIndex;

    template < typename T,typename ... Types >
    struct TupleIndex < T, std::tuple < T, Types... > > 
    {
    	static constexpr const std::size_t value = 0;
    };

    template < typename T, typename U, typename ... Types >
    struct TupleIndex < T, std::tuple < U, Types... > > 
    {
	    static constexpr const std::size_t value = 1 + TupleIndex < T, std::tuple < Types... > >::value;
    };

}


namespace fastlog
{
    ///  Набор типов для лога
    typedef std::tuple< char, uint32_t, uint64_t, int32_t, int64_t, double, CFastLogLine::string_literal_t, char* > SupportedTypes;

    ///  Параметр (из CFG): пишем время?
    const bool NeedWriteTime() noexcept
    {
        static bool bParamValue = true;

        if( false )
        {
            // TODO ...
            // Читать ключ настроек (ihi_cfg)
            // один раз!
        }

        return bParamValue;
    }


    bool SetCurrentTags(const str_t& tags) noexcept;
    const std::string GetCurrentTags(void) noexcept;


    char const * to_string(const LogLevel loglevel)
    {
        switch (loglevel)
        {
            case LogLevel::DBG :
                return "ОТЛАДКА";
            case LogLevel::INFO:
                return "ИНФОРМАЦИЯ";
            case LogLevel::WARN:
                return "ПРЕДУПРЕЖДЕНИЕ";
            case LogLevel::CRIT:
                return "ОШИБКА";
        }

        if(fastlog::LogLevel::NONE == loglevel)
            return "NONE";
        else
            return "XXXX";

        // return std::to_string((int)loglevel).c_str();
    }

    str_t event_type_text(const LogEventType val) noexcept
    {
        str_t value{};

        switch( val )
        {
        case LogEventType::User   :
            value = "User";
            break;
        case LogEventType::System :
            value = "System";
            break;
        case LogEventType::Request:
            value = "Request";
            break;
        case LogEventType::Timer  :
            value = "Timer";
            break;
        default:
            value = "UNDEF";
        }

        return value;
    }

    template < typename Arg >
    void CFastLogLine::encode(Arg arg)
    {
        *reinterpret_cast<Arg*>(buffer()) = arg;
        m_bytes_used += sizeof(Arg);
    }

    template < typename Arg >
    void CFastLogLine::encode(Arg arg, uint8_t type_id)
    {
        resize_buffer_if_needed(sizeof(Arg) + sizeof(uint8_t));
        encode< uint8_t >(type_id);
        encode< Arg >(arg);
    }

    CFastLogLine::CFastLogLine( LogEventType event, LogLevel level, char const * file, char const * function, uint32_t line)
      : m_bytes_used{ 0 }
      , m_buffer_size{ sizeof(m_stack_buffer) }
    {
        encode< uint64_t >(timestamp_now());
        encode< std::thread::id >(this_thread_id());
        encode< string_literal_t >(string_literal_t(file));
        encode< string_literal_t >(string_literal_t(function));
        encode< uint32_t >(line);
        encode< LogLevel >(level);
        encode< LogEventType >(event);
    }

    CFastLogLine::~CFastLogLine() noexcept
    {
        m_heap_buffer.reset();
    }

    bool CFastLogLine::stringify(std::ostream& os)
    {
        if( !os.good() )
        {
            std::cerr << "Bad state of <ostream>! \n";
            return false;
        }

        std::string sToken = "";
        const std::string tags = GetCurrentTags();

        char * b = !m_heap_buffer ? m_stack_buffer : m_heap_buffer.get();
        char const * const end = b + m_bytes_used;

        uint64_t timestamp = *reinterpret_cast < uint64_t * >(b); b += sizeof(uint64_t);
        std::thread::id threadid = *reinterpret_cast < std::thread::id * >(b); b += sizeof(std::thread::id);
        string_literal_t file = *reinterpret_cast < string_literal_t * >(b); b += sizeof(string_literal_t);
        string_literal_t function = *reinterpret_cast < string_literal_t * >(b); b += sizeof(string_literal_t);
        uint32_t line = *reinterpret_cast < uint32_t * >(b); b += sizeof(uint32_t);
        LogLevel loglevel = *reinterpret_cast < LogLevel * >(b); b += sizeof(LogLevel);
        LogEventType logEvtTyp = *reinterpret_cast< LogEventType* >(b); b += sizeof(LogEventType);
        // Этот токен сериализован как строка с null-символом в конце, в начале код типа (unused)
        if( m_hasGuid ) { sToken.assign(b + 1, b + sizeof(uid_t) + 1); b += 1 + xsize + 1; }

        format_timestamp(os, timestamp);

        os << "[THREAD:" << threadid << ']';
        os << "[LEVEL:" << to_string(loglevel) << ']';
        os << "[LINE:(" << file.m_s << ':' << function.m_s << ':' << line << ")]";
        os << "[TYPE:"  << event_type_text(logEvtTyp) << "]";

        // if( fastlog::LogEventType::Request == logEvtTyp )
        if( !sToken.empty() )
        {
            os << "[GUID:" << sToken.c_str() << "]";
        }
        if( !tags.empty() )
        {
            os << "[TAGS:" << tags.c_str() << ']';
        }
        if( this->m_forSave != 0 )
        {
            os << "[SAVE:" << ((1 == m_forSave) ? "True" : "False") << "]";
        }

        os << ' ';

        if( !stringify(os, b, end) )
        {
            // DLOG << "stringify(os) has <FALSE>\n";
            return false;
        }

        os << std::endl;

        if(loglevel >= LogLevel::CRIT)
        {
            os.flush();
        }

        return true;
    }

    template < typename Arg >
    char * decode(std::ostream & os, char * b, Arg * dummy)
    {
        Arg arg = *reinterpret_cast< Arg* >(b);
        os << arg;
        return b + sizeof(Arg);
    }

    template <>
    char * decode(std::ostream & os, char * b, CFastLogLine::string_literal_t * dummy)
    {
        CFastLogLine::string_literal_t s = *reinterpret_cast < CFastLogLine::string_literal_t * >(b);
        os << s.m_s;
        return b + sizeof(CFastLogLine::string_literal_t);
    }

    template<>
    char* decode(std::ostream & os, char* b, char** dummy)
    {
        if(nullptr == b)
        {
            std::cerr << "{LOGGER} decode(): Pointer is NULL!" << std::endl;
            return (b);
        }

        // DLOG << "{LOGGER} decode():" << b << std::endl;

        while(*b != '\0')
        {
            os << *b++;
        }

        return ++b;
    }

    bool CFastLogLine::stringify(std::ostream & os, char * start, char const * const end)
    {
        const char *xx = start;
        const char *yy = end;

        if (start == end)
        {
            //DLOG << "stringify() -- EXIT at begin!" << std::endl;
            return true;
        }

        bool  res = false;
        const int type_id = static_cast<int>( *start++ );  // start++;

        switch(type_id)
        {
        case 0:
            res = stringify(os, decode(os, start, static_cast<std::tuple_element<0, SupportedTypes>::type*>(nullptr)), end);
            break;
        case 1:
            res = stringify(os, decode(os, start, static_cast<std::tuple_element<1, SupportedTypes>::type*>(nullptr)), end);
            break;
        case 2:
            res = stringify(os, decode(os, start, static_cast<std::tuple_element<2, SupportedTypes>::type*>(nullptr)), end);
            break;
        case 3:
            res = stringify(os, decode(os, start, static_cast<std::tuple_element<3, SupportedTypes>::type*>(nullptr)), end);
            break;
        case 4:
            res = stringify(os, decode(os, start, static_cast<std::tuple_element<4, SupportedTypes>::type*>(nullptr)), end);
            break;
        case 5:
            res = stringify(os, decode(os, start, static_cast<std::tuple_element<5, SupportedTypes>::type*>(nullptr)), end);
            break;
        case 6:
            res = stringify(os, decode(os, start, static_cast<std::tuple_element<6, SupportedTypes>::type*>(nullptr)), end);
            break;
        case 7:
            res = stringify(os, decode(os, start, static_cast<std::tuple_element<7, SupportedTypes>::type*>(nullptr)), end);
            break;

        default:
            std::cerr << "stringify(): Type=<" << type_id << "> not valid here!\n";
#ifdef DEBUG
            {
                std::cout << "DEBUG bad type:[";
                if(xx != yy) {  putchar(*xx);  }
                std::cout << "] putchar() \n";
            }
#endif
            res = false;
        }

        // DLOG << "stringify() -- EXIT at end" << std::endl;
        return res; // os.good();
    }

    char* CFastLogLine::buffer()
    {
    	return !m_heap_buffer ? &m_stack_buffer[m_bytes_used] : &(m_heap_buffer.get())[m_bytes_used];
    }
    
    bool CFastLogLine::resize_buffer_if_needed(const size_t additional_bytes)
    {
        size_t const required_size = m_bytes_used + additional_bytes;

        if (required_size <= m_buffer_size)
            return false;

        if (!m_heap_buffer)
        {
            m_buffer_size = std::max(static_cast<size_t>(512), required_size);
            m_heap_buffer.reset( new char[m_buffer_size] );
            memcpy(m_heap_buffer.get(), m_stack_buffer, m_bytes_used);
        }
        else
        {
            m_buffer_size = std::max(static_cast<size_t>(2 * m_buffer_size), required_size);
            std::unique_ptr< char[] > heap_buffer( new char[m_buffer_size] );
            memcpy(heap_buffer.get(), m_heap_buffer.get(), m_bytes_used);
            m_heap_buffer.swap( heap_buffer );
        }

        return true;
    }

    void CFastLogLine::encode(char const * arg)
    {
        if( arg != nullptr )
        {
            encode_c_string(arg, strlen(arg));
        }
        else
        {
            std::cerr << "LOGGER: arg is NULL!" << std::endl;
        }
    }

    void CFastLogLine::encode(char * arg)
    {
        if( arg != nullptr )
        {
            encode_c_string(arg, strlen(arg));
        }
        else
        {
            std::cerr << "LOGGER: arg is NULL !" << std::endl;
        }
    }

    void CFastLogLine::encode_c_string(char const * arg, const size_t length)
    {
        if( !arg || length == 0 )
        {
            std::cerr << "LOGGER: Invalid string!" << std::endl;
            return;
        }

        resize_buffer_if_needed(1 + length + 1);
        char * b = buffer();

        auto type_id = TupleIndex < char *, SupportedTypes >::value;
        *reinterpret_cast<uint8_t*>(b++) = static_cast<uint8_t>(type_id);

        memcpy(b, arg, length);
        *(b + length) = 0;  // Null-символ

        m_bytes_used += (1 + length + 1);
    }

    void CFastLogLine::encode(string_literal_t arg)
    {
	    encode < string_literal_t >(arg, TupleIndex < string_literal_t, SupportedTypes >::value);
    }

    CFastLogLine& CFastLogLine::operator<<(std::string const & arg)
    {
	    encode_c_string(arg.c_str(), arg.length());
	    return *this;
    }

    CFastLogLine& CFastLogLine::operator<<(std::experimental::string_view arg) {
        encode_c_string(arg.data(), arg.length());
        return *this;
    }

    CFastLogLine& CFastLogLine::operator << (CTokenGUID const &arg)
    {
        if( !arg.IsEmpty() )
        {
            uid_t value{ };
            arg.Read(value);
            // std::cout << "CTokenGUID=" << arg.ToString() << std::endl;
            encode_c_string( &value.front(), value.size() );
        }

        m_hasGuid = arg.IsEmpty() ? 0 : 1;
        return *this;
    }

    CFastLogLine& CFastLogLine::operator << (SavingToDB const &arg)
    {
        // 1 - Yes, 2 - No, 0 - default
        m_forSave = (arg.saving ? 1 : 2);

        return *this;
    }

    CFastLogLine& CFastLogLine::operator<<(int32_t arg)
    {
	    encode < int32_t >(arg, TupleIndex < int32_t, SupportedTypes >::value);
	    return *this;
    }

    CFastLogLine& CFastLogLine::operator<<(uint32_t arg)
    {
	    encode < uint32_t >(arg, TupleIndex < uint32_t, SupportedTypes >::value);
	    return *this;
    }

    CFastLogLine& CFastLogLine::operator<<(int64_t arg)
    {
	    encode < int64_t >(arg, TupleIndex < int64_t, SupportedTypes >::value);
	    return *this;
    }

    CFastLogLine& CFastLogLine::operator<<(uint64_t arg)
    {
	    encode < uint64_t >(arg, TupleIndex < uint64_t, SupportedTypes >::value);
	    return *this;
    }

    CFastLogLine& CFastLogLine::operator<<(double arg)
    {
	    encode < double >(arg, TupleIndex < double, SupportedTypes >::value);
	    return *this;
    }

    CFastLogLine& CFastLogLine::operator<<(char arg)
    {
	    encode < char >(arg, TupleIndex < char, SupportedTypes >::value);
	    return *this;
    }

    struct BufferBase
    {
	virtual ~BufferBase() = default;
    	virtual void push(CFastLogLine && logline) = 0;
	virtual bool try_pop(CFastLogLine & logline) = 0;
    };

    struct SpinLock
    {
	SpinLock(std::atomic_flag & flag) : m_flag(flag)
	{
	    while (m_flag.test_and_set(std::memory_order_acquire));
	}

	~SpinLock()
	{
	    m_flag.clear(std::memory_order_release);
	}

    private:
	std::atomic_flag & m_flag;
    };

    /* Кольцевой буфер N писателей - 1 читатель  */
    class RingBuffer : public BufferBase
    {
    public:
    	struct alignas(64) Item
    	{
	        Item()
		    : flag{ ATOMIC_FLAG_INIT }
		    , written(0)
            , logline(LogEventType::Undef, LogLevel::DBG, nullptr, nullptr, 0)
	        {
	        }
	    
	        std::atomic_flag flag;
	        char written;
	        char padding[256 - sizeof(std::atomic_flag) - sizeof(char) - sizeof(CFastLogLine)];
	        CFastLogLine logline;
    	};
	
    	RingBuffer(size_t const size) 
    	    : m_size(size)
    	    , m_ring(static_cast<Item*>(std::malloc(size * sizeof(Item))))
    	    , m_write_index(0)
    	    , m_read_index(0)
    	{
    	    for (size_t i = 0; i < m_size; ++i)
    	    {
                new (&m_ring[i]) Item();
    	    }

            // Тут мы проверяем зачем-то размер структуры!
            static_assert(sizeof(Item) == 256, "Unexpected size != 256");
    	}

    	~RingBuffer()
    	{
    	    for (size_t i = 0; i < m_size; ++i)
    	    {
    		m_ring[i].~Item();
    	    }
    	    std::free(m_ring);
    	}

    	void push(CFastLogLine && logline) override
    	{
    	    unsigned int write_index = m_write_index.fetch_add(1, std::memory_order_relaxed) % m_size;
    	    Item & item = m_ring[write_index];
    	    SpinLock spinlock(item.flag);
	        item.logline = std::move(logline);
	        item.written = 1;
    	}

    	bool try_pop(CFastLogLine & logline) override
    	{
    	    Item & item = m_ring[m_read_index % m_size];
    	    SpinLock spinlock(item.flag);
    	    if (item.written == 1)
    	    {
    		    logline = std::move(item.logline);
    		    item.written = 0;
		        ++m_read_index;
    		    return true;
    	    }
    	    return false;
    	}

    	RingBuffer(RingBuffer const &) = delete;	
    	RingBuffer& operator=(RingBuffer const &) = delete;

    private:
    	size_t const m_size;
    	Item * m_ring;
    	std::atomic < unsigned int > m_write_index;
	char pad[64];
    	unsigned int m_read_index;
    };


    class Buffer
    {
    public:
    	struct Item
    	{
    	    Item(CFastLogLine && CFastLogLine) : logline(std::move(CFastLogLine)) {}
    	    char padding[256 - sizeof(CFastLogLine)];
	        CFastLogLine logline;
    	};

	    static constexpr const size_t size = 32768; // 8MB. Helps reduce memory fragmentation

    	Buffer() : m_buffer(static_cast<Item*>(std::malloc(size * sizeof(Item))))
    	{
    	    for (size_t i = 0; i <= size; ++i)
    	    {
    		m_write_state[i].store(0, std::memory_order_relaxed);
    	    }
	        static_assert(sizeof(Item) == 256, "Unexpected size != 256");
    	}

    	~Buffer()
    	{
	        unsigned int write_count = m_write_state[size].load();
	        for (size_t i = 0; i < write_count; ++i)
    	    {
    		    m_buffer[i].~Item();
    	    }
    	    std::free(m_buffer);
    	}

	    //Возвращает true если требуется переключиться на следующий буфер
    	bool push(CFastLogLine && logline, unsigned int const write_index)
    	{
	        new (&m_buffer[write_index]) Item(std::move(logline));
	        m_write_state[write_index].store(1, std::memory_order_release);
	        return m_write_state[size].fetch_add(1, std::memory_order_acquire) + 1 == size;
    	}

    	bool try_pop(CFastLogLine & logline, unsigned int const read_index)
    	{
	        if (m_write_state[read_index].load(std::memory_order_acquire))
	        {
		        Item & item = m_buffer[read_index];
		        logline = std::move(item.logline);
		        return true;
	        }
	        return false;
    	}

    	Buffer(Buffer const &) = delete;	
    	Buffer& operator=(Buffer const &) = delete;

    private:
    	Item * m_buffer;
    	std::atomic < unsigned int > m_write_state[size + 1];
    };

    class QueueBuffer : public BufferBase
    {
        public:
        QueueBuffer(QueueBuffer const &) = delete;
        QueueBuffer& operator=(QueueBuffer const &) = delete;

        QueueBuffer() : m_current_read_buffer{nullptr}
                    , m_write_index(0)
                  , m_flag{ATOMIC_FLAG_INIT}
                  , m_read_index(0)
        {
            setup_next_write_buffer();
        }

            void push(CFastLogLine && logline) override
            {
                unsigned int write_index = m_write_index.fetch_add(1, std::memory_order_relaxed);
                if (write_index < Buffer::size)
                {
                    if (m_current_write_buffer.load(std::memory_order_acquire)->push(std::move(logline), write_index))
                    {
                        setup_next_write_buffer();
                    }
                }
                else
                {
                    while (m_write_index.load(std::memory_order_acquire) >= Buffer::size);
                        push(std::move(logline));
                }
            }

            bool try_pop(CFastLogLine & logline) override
            {
                if (m_current_read_buffer == nullptr)
                    m_current_read_buffer = get_next_read_buffer();

                Buffer * read_buffer = m_current_read_buffer;

                if (read_buffer == nullptr)
                    return false;

                if (bool success = read_buffer->try_pop(logline, m_read_index))
                {
                    m_read_index++;
                    if (m_read_index == Buffer::size)
                    {
                        m_read_index = 0;
                        m_current_read_buffer = nullptr;
                        SpinLock spinlock(m_flag);
                        m_buffers.pop();
                    }
                    return true;
                }

            return false;
        }

        private:
        void setup_next_write_buffer()
        {
            std::unique_ptr < Buffer > next_write_buffer(new Buffer());
            m_current_write_buffer.store(next_write_buffer.get(), std::memory_order_release);
            SpinLock spinlock(m_flag);
            m_buffers.push(std::move(next_write_buffer));
            m_write_index.store(0, std::memory_order_relaxed);
        }

        Buffer * get_next_read_buffer()
        {
            SpinLock spinlock(m_flag);
            return m_buffers.empty() ? nullptr : m_buffers.front().get();
        }

        private:
        std::queue < std::unique_ptr < Buffer > > m_buffers;
            std::atomic < Buffer * > m_current_write_buffer;
        Buffer * m_current_read_buffer;
            std::atomic < unsigned int > m_write_index;
        std::atomic_flag m_flag;
            unsigned int m_read_index;
        };

        class FileWriter
        {
        public:
        FileWriter(std::string const & log_directory, std::string const & log_file_name, 
            uint32_t log_file_roll_size_mb, std::string const & tempLogPath) 

        : m_log_file_roll_size_bytes(log_file_roll_size_mb * 1024 * 1024)
            , m_name(log_directory + log_file_name)
            , m_tempLogPath(tempLogPath)
        {
            roll_file();
        }

        void write(CFastLogLine & logline)
        {
            auto pos = m_os->tellp();

            logline.stringify(*m_os);

            m_bytes_written += m_os->tellp() - pos;

            if (m_bytes_written > m_log_file_roll_size_bytes)
            {
                roll_file();
            }
        }

        private:

        inline bool is_file_exists (const std::string& name)
        {
            struct stat buffer;
            return (stat (name.c_str(), &buffer) == 0);
        }

        void roll_file()
        {

            if (m_os)
            {
                m_os->flush();
                m_os->close();
            }

            std::string base_log_file_name = m_name;
            base_log_file_name.append(".");
            std::string log_file_name = base_log_file_name + (std::to_string(++m_file_number));
            log_file_name.append(".txt");

            while (is_file_exists(log_file_name))
            {
                log_file_name = base_log_file_name + (std::to_string(++m_file_number));
                log_file_name.append(".txt");
            }

            //Здесь записать в файл *.logfilename название текущего лога
            if(!m_tempLogPath.empty()) {

                try
                {
                    std::ofstream tmpLog;

                    if(tmpLog) {

                        tmpLog.open(m_tempLogPath, std::ofstream::out | std::ofstream::trunc);

                        if(tmpLog.is_open()) {

                            tmpLog << log_file_name << '\n';
                            tmpLog.close();
                        }
                    }
                }
                catch (std::ios_base::failure& e)
                {
                    std::cerr << "Ошибка при открытии файла " << m_tempLogPath << " - "<< e.what() << '\n';
                }
            }
            
            m_bytes_written = 0;
            m_os.reset(new std::ofstream());

            std::ios_base::iostate exceptionMaskPrev = m_os->exceptions();
            std::ios_base::iostate exceptionMask = exceptionMaskPrev | std::ios::failbit;

            m_os->exceptions(exceptionMask);

            try
            {
                m_os->open(log_file_name, std::ofstream::out | std::ofstream::trunc);
            }
            catch (std::ios_base::failure& e)
            {
                //std::cerr << e.what() << '\n';
                std::cerr << "Ошибка при открытии файла " << log_file_name << " - "<< e.what() << '\n';
                throw;
            }

            std::cerr << log_file_name.c_str() << std::endl;
            m_os->exceptions(exceptionMaskPrev);
        }

        private:

        uint32_t m_file_number = 0;
        std::streamoff m_bytes_written = 0;
        uint32_t const m_log_file_roll_size_bytes;
        std::string const m_name;
        std::unique_ptr < std::ofstream > m_os;

        std::string m_tempLogPath{};
    };

    /// класс логгера
    class CFastLogger final
    {
    public:
        CFastLogger(NonGuaranteedLogger ngl, std::string const & log_directory, std::string const & log_file_name, 
            uint32_t log_file_roll_size_mb, std::string const & tempLogPath)
            : m_state(State::INIT)
            , m_buffer_base(new RingBuffer(std::max(1u, ngl.ring_buffer_size_mb) * 1024 * 4))
            , m_file_writer(log_directory, log_file_name, std::max(1u, log_file_roll_size_mb), tempLogPath)
            , m_thread(&CFastLogger::pop, this)
        {
            m_state.store(State::READY, std::memory_order_release);
        }

        CFastLogger(GuaranteedLogger gl, std::string const & log_directory, std::string const & log_file_name, 
            uint32_t log_file_roll_size_mb, std::string const & tempLogPath)
            : m_state(State::INIT)
            , m_buffer_base(new QueueBuffer())
            , m_file_writer(log_directory, log_file_name, std::max(1u, log_file_roll_size_mb), tempLogPath)
            , m_thread(&CFastLogger::pop, this)
        {
            m_state.store(State::READY, std::memory_order_release);
        }

        ~CFastLogger()
        {
            StopWork();
            // m_state.store(State::SHUTDOWN);
            m_thread.join();
        }

        void add(CFastLogLine&& logline)
        {
            m_buffer_base->push( std::move(logline) );
        }

        void pop(void)  // эта функция работает в отдельном потоке!
        {
            // Wait for constructor to complete and pull all stores done there to this thread / core.
            while (m_state.load(std::memory_order_acquire) == State::INIT)
            {
                std::this_thread::sleep_for(std::chrono::microseconds(50));
            }

            CFastLogLine logline(LogEventType::Undef, LogLevel::DBG, nullptr, nullptr, 0);

            // logline.SetType(LogEventType::System);

            while(m_state.load() == State::READY)
            {
                if (m_buffer_base->try_pop(logline))
                    m_file_writer.write(logline);
                else
                    std::this_thread::sleep_for(std::chrono::microseconds(50));
            }

            // Pop and log all remaining entries
            while(m_buffer_base->try_pop(logline))
            {
                m_file_writer.write(logline);
            }
        }

        const bool ready_for_write(void) const
        {
            return (State::READY == m_state.load());
        }

        const str_t& GetOptTags(void) const noexcept
        {
            return m_OptionalTags;
        }

        void SetOptTags(const str_t& str) noexcept
        {
            m_OptionalTags = str;
        }

        void StopWork(void) noexcept
        {
            // std::cout << "StopWork()" << std::endl;
            m_state.store(State::SHUTDOWN);
        }

    private:

        str_t m_OptionalTags = "";

        enum class State
        {
            INIT,
            READY,
            SHUTDOWN
        };

        std::atomic< State > m_state;
        std::unique_ptr< BufferBase > m_buffer_base;
        FileWriter m_file_writer;
        std::thread m_thread;
    };


    std::unique_ptr<CFastLogger>  fastlogger;
    std::atomic<CFastLogger*>     atomic_fastlogger;

    std::atomic<unsigned int> loglevel = {0};


    bool SetCurrentTags(const str_t& tags) noexcept
    {
        if( atomic_fastlogger.load(std::memory_order_acquire) != nullptr )
        {
            // atomic_fastlogger.load(std::memory_order_acquire)->SetOptTags(tags);
            fastlogger->SetOptTags( tags );

            return true;
        }
        else
        {
            // nothing...
            return false;
        }
    }

    const std::string GetCurrentTags(void) noexcept
    {
        if( atomic_fastlogger.load(std::memory_order_acquire) != nullptr )
        {
            return fastlogger->GetOptTags();
        }
        else
        {
            return std::string{"NO_DATA"};
        }
    }


    bool CLogHelper::operator <= (CFastLogLine& line)
    {
        // if( !atomic_fastlogger ) return false;
        if( atomic_fastlogger.load(std::memory_order_acquire) != nullptr )
        {
            atomic_fastlogger.load(std::memory_order_acquire)->add( std::move(line) );

            return true;
        }
        else
        {
            return false;
        }
    }


    void initialize(NonGuaranteedLogger ngl, std::string const & log_dir, std::string const & log_name, 
         uint32_t size_mb, std::string const & log_path)
    {
	    fastlogger.reset( new CFastLogger{ ngl, log_dir, log_name, size_mb, log_path } );
	    atomic_fastlogger.store(fastlogger.get(), std::memory_order_seq_cst);
        std::cout << "Запущено логирование (в файл):" << log_name << std::endl;
    }

    void initialize(GuaranteedLogger gl, std::string const & log_dir, std::string const & log_name, 
         uint32_t size_mb, std::string const & log_path)
    {
	    fastlogger.reset( new CFastLogger{ gl, log_dir, log_name, size_mb, log_path } );
	    atomic_fastlogger.store(fastlogger.get(), std::memory_order_seq_cst);
        std::cout << "Запущено логирование (в файл):" << log_name << std::endl;
    }


    unsigned long LoggerPtrValue(void)
    {
        return reinterpret_cast<unsigned long>( fastlogger.get() );
    }

    void log_add_tag( const str_t str )
    {
        // TODO : Поддержка добавления и удаления!

        SetCurrentTags(str);
    }

    void set_log_level(LogLevel level)
    {
        loglevel.store(static_cast<unsigned int>(level), std::memory_order_release);
    }

    unsigned int get_log_level(void)
    {
        unsigned int val = 0;

        if( is_opened() )
        {
            val = loglevel.load(std::memory_order_relaxed);
        }

        return val;
    }

    bool is_logged(const LogLevel level)
    {
        if( !is_opened() ) return false;

        return static_cast<unsigned int>(level) >= loglevel.load(std::memory_order_relaxed);
    }

    bool is_opened(void)
    {
        // if( fastlogger )
        if( atomic_fastlogger.load(std::memory_order_acquire) != nullptr )
        {
            return fastlogger->ready_for_write();
        }
        else
        {
            return false;
        }
    }

    void close_log(void)
    {
        // DLOG << "close_log() calling..." << std::endl;
        // Сброс сохранён.указ.
        atomic_fastlogger.store(nullptr, std::memory_order_seq_cst);

        if( fastlogger )
        {
            fastlogger->StopWork();    // дать время на завершение...
            std::this_thread::sleep_for( std::chrono::microseconds(200) );
            fastlogger.reset(nullptr); // удаление объекта логгера!
        }

        std::cout << ">> Завершено логирования (в файл)." << std::endl;
    }

}   // namespace 'fastlogger'

