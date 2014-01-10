#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <limits>
#include <stdexcept>
#include <stdint.h>
#include <sys/time.h>
#include <unistd.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <readline/history.h>
#include <readline/readline.h>

using std::cerr;
using std::cout;

namespace CPP = CryptoPP;

const long ACCEPTABLE_CARD_RESPONSE_TIME_US = 100000;
const size_t AES_KEY_LENGTH = 32;

namespace {

timeval timeOfDay()
{
  timeval tv;
  gettimeofday(&tv, NULL);
  return tv;
}

template <typename T>
std::string toString(const T &value)
{
  std::string result;
  std::stringstream os;
  os << value;
  os >> result;
  return result;
}

bool verifyHex(const std::string &s)
{
  if (s.size()%2 != 0)
    return false;
  for (size_t i = 0; i < s.size(); ++i)
    if ((s[i] < '0' || s[i] > '9')
    &&  (s[i] < 'a' || s[i] > 'f')
    &&  (s[i] < 'A' || s[i] > 'F'))
      return false;
  return true;
}

std::string bbToHex(const CPP::SecByteBlock &bb)
{
  std::string result;
  result.resize(bb.size()*2);
  for (size_t i = 0; i < bb.size(); ++i)
    sprintf(&result[i*2], "%02x", bb[i]);
  return result;
}

CPP::SecByteBlock hexToBb(const std::string &s)
{
  if (!verifyHex(s))
    throw std::runtime_error("String is not valid base16");
  CPP::SecByteBlock result(s.size()/2);
  unsigned x;
  for (size_t i = 0; i < result.size(); ++i)
  {
    sscanf(&s[i*2], "%02x", &x);
    result[i] = x;
  }
  return result;
}

std::string readError(const std::string &file)
{
  return "Couldn't open file \"" + file + "\" for reading";
}

std::string writeError(const std::string &file)
{
  return "Couldn't open file \"" + file + "\" for writing";
}

}

/***********************************************/

struct State
{
  State() { }

  State(const byte *iv, size_t iv_len, const byte *key, size_t key_len)
  : m_iv(iv, iv_len), m_key(key, key_len) { }

  State(CPP::RandomNumberGenerator &rng)
  {
    m_iv.resize(CPP::AES::BLOCKSIZE);
    m_key.resize(AES_KEY_LENGTH);
    rng.GenerateBlock(m_iv, m_iv.size());
    rng.GenerateBlock(m_key, m_key.size());
  }

  const CPP::SecByteBlock &iv() const { return m_iv; }
  const CPP::SecByteBlock &key() const { return m_key; }

  bool operator==(const State &rhs) const
  {
    return m_iv  == rhs.m_iv
        && m_key == rhs.m_key;
  }

  friend std::istream &operator>>(std::istream &is, State &st);

private:
  CPP::SecByteBlock m_iv;
  CPP::SecByteBlock m_key;
};

std::ostream &operator<<(std::ostream &os, const State &st)
{
  os << bbToHex(st.iv()) << " " << bbToHex(st.key());
  return os;
}

std::istream &operator>>(std::istream &is, State &st)
{
  std::string tmp;
  is >> tmp;
  st.m_iv = hexToBb(tmp);
  is >> tmp;
  st.m_key = hexToBb(tmp);
  return is;
}

CPP::SecByteBlock encrypt(const State &st, const CPP::SecByteBlock &msg)
{
  CPP::SecByteBlock result(msg.size());
  CPP::CFB_Mode<CPP::AES>::Encryption enc(st.key(), st.key().size(), st.iv());
  enc.ProcessData(result, msg, msg.size());
  return result;
}

CPP::SecByteBlock decrypt(const State &st, const CPP::SecByteBlock &msg)
{
  CPP::SecByteBlock result(msg.size());
  CPP::CFB_Mode<CPP::AES>::Decryption dec(st.key(), st.key().size(), st.iv());
  dec.ProcessData(result, msg, msg.size());
  return result;
}

/***********************************************/

struct Card
{
  Card(uint16_t id, CPP::RandomNumberGenerator &rng)
  : m_id(id), m_state(rng) { }

  Card(const char *file)
  {
    std::ifstream f(file);
    if (!f.is_open())
      throw std::runtime_error(readError(file));
    f >> *this;
  }

  uint16_t id() const { return m_id; }
  const State &state() const { return m_state; }

  CPP::SecByteBlock challengeResponse(const CPP::SecByteBlock &challenge, bool delay) const
  {
    if (delay)
      usleep(rand()%(ACCEPTABLE_CARD_RESPONSE_TIME_US*2));
    return encrypt(m_state, challenge);
  }

  void updateState(const CPP::SecByteBlock &m_2)
  {
    CPP::SecByteBlock serialized_new_st = decrypt(m_state, m_2);
    m_state = State(serialized_new_st.BytePtr(), CPP::AES::BLOCKSIZE,
                    serialized_new_st.BytePtr() + CPP::AES::BLOCKSIZE, AES_KEY_LENGTH);
  }

  friend std::istream &operator>>(std::istream &is, Card &c);

private:
  uint16_t m_id;
  State m_state;
};

std::ostream &operator<<(std::ostream &os, const Card &c)
{
  os << c.id() << " " << c.state();
  return os;
}

std::istream &operator>>(std::istream &is, Card &c)
{
  is >> c.m_id;
  is >> c.m_state;
  return is;
}

/***********************************************/

struct Terminal
{
  Terminal(const char *file)
  {
    std::ifstream f(file);
    if (!f.is_open())
      throw std::runtime_error(readError(file));
    f >> *this;
  }

  bool authenticate(CPP::RandomNumberGenerator &rng, Card &card)
  {
    // <- id
    uint16_t id = card.id();

    // -> r
    CPP::SecByteBlock r(8);
    rng.GenerateBlock(r, r.size());
    timeval t = timeOfDay();

    // <- m_1
    CPP::SecByteBlock m_1 = card.challengeResponse(r, false);
    timeval t_prim = timeOfDay();
    if ((t_prim.tv_sec > t.tv_sec)
    ||  (t_prim.tv_usec - t.tv_usec) > ACCEPTABLE_CARD_RESPONSE_TIME_US)
    {
      cerr << "Card response time was too long, aborting.\n";
      return false;
    }

    bool prev_ok = decrypt(m_states[id].first,  m_1) == r;
    bool curr_ok = decrypt(m_states[id].second, m_1) == r;
    if (prev_ok || curr_ok)
    {
      State good_st;
      if (prev_ok)
      {
        cout << "Warning: card and terminal are not fully synchronized.\n";
        good_st = m_states[id].first;
      }
      else
        good_st = m_states[id].second;

      // take new, different state at random
      State new_st;
      do
        new_st = State(rng);
      while (new_st == good_st);

      m_states[id].first = good_st;
      m_states[id].second = new_st;

      // -> m_2
      CPP::SecByteBlock serialized_new_st;
      serialized_new_st += new_st.iv();
      serialized_new_st += new_st.key();
      card.updateState(encrypt(good_st, serialized_new_st));

      return true;
    }
    else
    {
      cerr << "Card has an incorrect state (it most likely has been cloned), aborting.\n";
      return false;
    }
  }

  const std::vector< std::pair<State, State> > &states() const { return m_states; }

  friend std::istream &operator>>(std::istream &is, Terminal &t);

private:
  std::vector< std::pair<State, State> > m_states;
};

std::istream &operator>>(std::istream &is, Terminal &t)
{
  t.m_states.resize(std::numeric_limits<uint16_t>::max() + 1);
  for (uint32_t i = 0; i <= std::numeric_limits<uint16_t>::max(); ++i)
  {
    is >> t.m_states[i].first;
    is >> t.m_states[i].second;
  }
  return is;
}

/***********************************************/

void serialize(const Terminal &t, const char *file)
{
  std::ofstream f(file);
  if (!f.is_open())
    throw std::runtime_error(writeError(file));
  for (size_t i = 0; i < t.states().size(); ++i)
    f << t.states()[i].first << " " << t.states()[i].second << "\n";
  f.close();
}

void serialize(const Card &c, const char *file)
{
  std::ofstream f(file);
  if (!f.is_open())
    throw std::runtime_error(writeError(file));
  f << c;
  f.close();
}

/***********************************************/

int main(int argc, char **argv)
{
  if (argc < 2)
  {
    cerr << "Usage: " << argv[0] << " <init|auth> [args..]\n";
    return 1;
  }

  srand(time(NULL));
  CPP::AutoSeededRandomPool rng;

  if (strcmp(argv[1], "init") == 0)
  {
    if (argc < 4)
    {
      cerr << "Usage: " << argv[0] << " init <terminal_state_file> <cards_directory>\n";
      return 1;
    }

    const char *terminal_file = argv[2];
    const std::string cards_directory = argv[3];

    std::ofstream terminal(terminal_file);
    if (!terminal.is_open())
    {
      cerr << writeError(terminal_file) << "\n";
      return 1;
    }

    for (uint32_t i = 0; i <= std::numeric_limits<uint16_t>::max(); ++i)
    {
      Card c(i, rng);
      terminal << State(rng) << " " << c.state() << "\n";

      const std::string card_file = cards_directory + "/" + toString(i) + ".txt";
      std::ofstream card(card_file.c_str());
      if (!card.is_open())
      {
        cerr << writeError(card_file) << "\n";
        return 1;
      }
      card << c << "\n";
      card.close();
    }
    terminal.close();
  }
  else if (strcmp(argv[1], "auth") == 0)
  {
    if (argc < 3)
    {
      cerr << "Usage: " << argv[0] << " auth <terminal_state_file>\n";
      return 1;
    }

    cout << "Reading terminal state... " << std::flush;
    Terminal terminal(argv[2]);
    cout << "Done.\n";

    while (true)
    {
      char *input = readline("> ");
      if (input == NULL)
      {
        cout << "\n";
        break;
      }
      else
      {
        try
        {
          Card card(input);

          if (terminal.authenticate(rng, card))
          {
            cout << "Success, opening door...\n";
            serialize(card, input);
          }
        }
        catch (std::exception &e)
        {
          cerr << "Error: " << e.what() << "\n";
        }
      }
      add_history(input);
      free(input);
    }

    cout << "Serializing terminal state... " << std::flush;
    serialize(terminal, argv[2]);
    cout << "Done.\n";
  }
  else
  {
    cerr << "Invalid command: " << argv[1] << "\n";
    return 1;
  }

  return 0;
}
