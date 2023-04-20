import menu from './assets/Menu.png';
import Banner from './Components/Banner.js';
import back from './assets/Return.png';
import './styles/App.css';
import Content from './Components/Content.js';
import Footer from './Components/Footer.js';
import Menu from './Components/Menu';
import { useState } from 'react'

const myModel = [
  { text: 'Sklearn', value: 'sklearn' },
  { text: 'Python', value: 'python'},
  { text: 'C++', value: 'C++'},
];

function App() {
  const [isMenu, setIsMenu] = useState(false)
  const [isContent, setIsContent] = useState(0)
  const [selectedModel, setSelectedModel] = useState(myModel[0]);
  function switchMenu(){
    if(isMenu){
      setIsMenu(false)
    }
    else{
      setIsMenu(true)
    }
  }
  
  
  return isMenu ? (
    <div className="App">
      
        <Banner>
        
      
          <img src={back} alt='menu' className='mia-logo' onClick={()=> switchMenu()} />
          
          <h1 className='mia-title'>Mus'IA</h1>
        </Banner>
        <Menu selectedModel={selectedModel} setSelectedModel={setSelectedModel} />
        <Footer />
      
    </div>
  ) : (
    <div className='App'>
      <Banner>
          {isContent === 0 ?(
            <img src={menu} alt='logo-menu' className='mia-logo'  onClick={()=> switchMenu()} />)
            :(
              <img src={back} alt='menu' className='mia-logo' onClick={()=> setIsContent(0)} />)
          }
          
          <h1 className='mia-title'>Mus'IA</h1>
        </Banner>
      <Content selectedModel={selectedModel} isContent={isContent} setIsContent={setIsContent} />
      <Footer />
    </div>
  );
}

export default App;
