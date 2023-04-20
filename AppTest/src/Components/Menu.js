import '../styles/Menu.css';
import Select from 'react-select';

const options = [
  { value: 'sklearn', label: 'Sklearn' },
  { value: 'python', label: 'Python' },
  { value: 'C++', label: 'C++' },
];

function Menu({selectedModel,setSelectedModel}) {
  
  const handleChange = selectedModel => {
    setSelectedModel(selectedModel);
    if (selectedModel && selectedModel.value === 'C++') {
      alert('C++ is not available yet');
    }
  };
  const customStyles = {
    singleValue: (base) => ({ ...base, color: 'black' }),
    option: (styles) => ({ ...styles, color: 'black' }),
    defaultValue: (styles) => ({ ...styles, color: 'black' })
  };
  const customStylesWrapper = {
    singleValue: (base) => ({ ...base, color: 'black' }),
    option: (styles) => ({ ...styles, color: 'black' }),
  };
  return (
    <div className="Menu">
      <Select
        className="Menu-select"
        classNamePrefix="Menu"
        options={options}
        value={selectedModel}
        onChange={handleChange}
        defaultValue={options[0]}
        getOptionLabel={(option) => option.label}
        getOptionValue={(option) => option.value}
        
        styles={customStyles}
      />
        <p>
          Cette application a été créée dans le but d'apprendre l'IA dans le cadre de notre projet de 4e année
        </p>
        
        <div className='wrapper' styles={customStylesWrapper}>
          <div className='carousel'>
            <div className='carousel__item'>
              <div className='carousel__item-head'>
                🎻
              </div>
              <div className='carousel__item-body' style={{color: 'black'}}>
                <p className='title'>classic</p>
                <p>Mozart</p>
              </div>
            </div>
            <div className='carousel__item'>
              <div className='carousel__item-head'>
                🎸
              </div>
              <div className='carousel__item-body' style={{color: 'black'}}>
                <p className='title'>Rock</p>
                <p>AC/DC</p>
              </div>
            </div>
            <div className='carousel__item'>
              <div className='carousel__item-head'>
                🕺
              </div>
              <div className='carousel__item-body' style={{color: 'black'}}>
                <p className='title'>Disco-Boogie</p>
                <p>Earth, Wind & Fire</p>
              </div>
            </div>
            <div className='carousel__item'>
              <div className='carousel__item-head'>
                ⚡
              </div>
              <div className='carousel__item-body'style={{color: 'black'}}>
                <p className='title'>Electro</p>
                <p>Martin Garrix</p>
              </div>
            </div>
            <div className='carousel__item'>
              <div className='carousel__item-head'>
                🧢
              </div>
              <div className='carousel__item-body'style={{color: 'black'}}>
                <p className='title'>Hiphop-Rap</p>
                <p>Eminem</p>
              </div>
            </div>
            <div className='carousel__item'>
              <div className='carousel__item-head'>
                🎷
              </div>
              <div className='carousel__item-body' style={{color: 'black'}}>
                <p className='title'>Jazz</p>
                <p>Louis Amstrong</p>
              </div>
            </div>
            <div className='carousel__item'>
              <div className='carousel__item-head'>
                🌇
              </div>
              <div className='carousel__item-body' style={{color: 'black'}}>
                <p className='title'>Lofi</p>
                <p>Lofi Girl</p>
              </div>
            </div>
            <div className='carousel__item'>
              <div className='carousel__item-head'>
                ⚔️
              </div>
              <div className='carousel__item-body' style={{color: 'black'}}>
                <p className='title'>Medieval</p>
                <p>Musique de Tavernes</p>
              </div>
            </div>
            <div className='carousel__item'>
              <div className='carousel__item-head'>
                🎤
              </div>
              <div className='carousel__item-body' style={{color: 'black'}}>
                <p className='title'>Pop</p>
                <p>Madonna</p>
              </div>
            </div>
            <div className='carousel__item'>
              <div className='carousel__item-head'>
                💽
              </div>
              <div className='carousel__item-body' style={{color: 'black'}}>
                <p className='title'>R&B-Soul</p>
                <p>Marvin Gaye</p>
              </div>
            </div>
            <div className='carousel__item'>
              <div className='carousel__item-head'>
                🦜
              </div>
              <div className='carousel__item-body' style={{color: 'black'}}>
                <p className='title'>Reggae</p>
                <p>Bob Marley</p>
              </div>
            </div>
            <div className='carousel__item'>
              <div className='carousel__item-head'>
                🕹️
              </div>
              <div className='carousel__item-body' style={{color: 'black'}}>
                <p className='title'>Retro</p>
                <p>UnderTale</p>
              </div>
            </div>
          
          </div>
        </div>
      
    </div>
  );
}

export default Menu;
